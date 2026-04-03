from __future__ import annotations

import ipaddress
import time
from dataclasses import asdict
from datetime import datetime, timezone
from collections import Counter
from typing import Any, Dict, Iterable, List, Set, Tuple

from .config import SIEMConfig
from .models import Alert, ConnectionEvent, FirewallBlockEvent, NetworkEvent, PacketEvent

# States that indicate a locally-listening server socket — not an active
# outbound/inbound data connection.  Flagging these produces constant noise
# for normal Windows services (SMB/445, RDP/3389, etc.).
_PASSIVE_STATES = frozenset({"LISTEN", "NONE", "TIME_WAIT", "CLOSE_WAIT", "CLOSED"})

_COMMON_EXTERNAL_SERVICE_PORTS = frozenset({53, 80, 123, 443, 853})


class AnomalyDetector:
    def __init__(self, config: SIEMConfig) -> None:
        self.config = config
        self._baseline_per_interface: Dict[str, float] = {}
        # Cooldown tracker: maps (rule_name, detail_key) -> last_fired monotonic time
        self._last_alerted: Dict[Tuple, float] = {}
        self._firewall_attempt_times: Dict[Tuple[str, int], List[float]] = {}
        self._firewall_source_times: Dict[str, List[float]] = {}
        self._beacon_observations: Dict[Tuple[str, str, int], List[float]] = {}
        self._exfil_observations: Dict[Tuple[str, str, int], List[Tuple[float, int]]] = {}
        self._seen_local_service_ports: Dict[str, Set[int]] = {}
        self._rule_enabled: Dict[str, bool] = {}
        self._rule_mute_until_epoch: Dict[str, float] = {}
        self._rule_threshold_overrides: Dict[str, float] = {}
        self._suppression_rules: List[Dict[str, str]] = []
        self._baseline_learning_started_epoch = time.time()
        self._baseline_learning_samples: Dict[str, List[float]] = {}

    def get_controls(self) -> Dict[str, Any]:
        return {
            "rule_enabled": dict(self._rule_enabled),
            "rule_mute_until_epoch": dict(self._rule_mute_until_epoch),
            "rule_threshold_overrides": dict(self._rule_threshold_overrides),
            "suppression_rules": list(self._suppression_rules),
        }

    def set_controls(self, controls: Dict[str, Any]) -> None:
        self._rule_enabled = {
            str(k): bool(v)
            for k, v in dict(controls.get("rule_enabled", {})).items()
        }
        self._rule_mute_until_epoch = {
            str(k): float(v)
            for k, v in dict(controls.get("rule_mute_until_epoch", {})).items()
            if float(v) > 0
        }
        self._rule_threshold_overrides = {
            str(k): float(v)
            for k, v in dict(controls.get("rule_threshold_overrides", {})).items()
            if float(v) > 0
        }
        self._suppression_rules = [
            {
                "rule": str(r.get("rule", "") or "").strip(),
                "interface": str(r.get("interface", "") or "").strip(),
                "contains": str(r.get("contains", "") or "").strip().lower(),
                "reason": str(r.get("reason", "") or "").strip(),
            }
            for r in list(controls.get("suppression_rules", []))
            if isinstance(r, dict)
        ]

    def get_baseline_state(self) -> Dict[str, Any]:
        now = time.time()
        elapsed_hours = (now - self._baseline_learning_started_epoch) / 3600.0
        max_observed = [max(v) for v in self._baseline_learning_samples.values() if v]
        suggested_max = (max(max_observed) * 1.3) if max_observed else self.config.max_bytes_per_second
        return {
            "enabled": bool(self.config.baseline_learning_enabled),
            "hours_elapsed": round(elapsed_hours, 2),
            "hours_target": int(self.config.baseline_learning_hours),
            "learning_active": bool(self.config.baseline_learning_enabled and elapsed_hours < float(self.config.baseline_learning_hours)),
            "suggested_max_bytes_per_second": round(suggested_max, 2),
        }

    def _rule_threshold(self, rule: str, default: float) -> float:
        return float(self._rule_threshold_overrides.get(rule, default))

    def _is_rule_enabled(self, rule: str) -> bool:
        return bool(self._rule_enabled.get(rule, True))

    def _is_rule_muted(self, rule: str) -> bool:
        return float(self._rule_mute_until_epoch.get(rule, 0.0)) > time.time()

    def _suppression_reason(self, alert: Alert) -> str:
        for s in self._suppression_rules:
            srule = s.get("rule", "")
            siface = s.get("interface", "")
            scontains = s.get("contains", "")
            if srule and srule != alert.rule:
                continue
            if siface and siface != alert.interface:
                continue
            if scontains and scontains not in alert.message.lower():
                continue
            return s.get("reason", "suppressed") or "suppressed"
        return ""

    def _finalize_alerts(self, alerts: List[Alert]) -> List[Alert]:
        output: List[Alert] = []
        for a in alerts:
            if not self._is_rule_enabled(a.rule):
                continue
            if self._is_rule_muted(a.rule):
                continue
            reason = self._suppression_reason(a)
            if reason:
                continue
            output.append(a)
        return output

    @staticmethod
    def _is_public_ip(ip: str) -> bool:
        if not ip:
            return False
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_reserved
            or parsed.is_unspecified
        )

    @staticmethod
    def _is_active_connection(event: ConnectionEvent) -> bool:
        return (event.status or "").upper() not in _PASSIVE_STATES

    def _cooldown_allows(self, key: Tuple, now: float) -> bool:
        cooldown_seconds = max(1, int(self.config.detector_cooldown_seconds))
        if now - self._last_alerted.get(key, 0.0) < cooldown_seconds:
            return False
        self._last_alerted[key] = now
        return True

    def evaluate(self, events: Iterable[NetworkEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        baseline_state = self.get_baseline_state()
        learning_active = bool(baseline_state.get("learning_active"))

        for event in events:
            current_bps = max(event.bytes_sent_per_sec, event.bytes_recv_per_sec)
            baseline = self._baseline_per_interface.get(event.interface, current_bps)
            self._baseline_learning_samples.setdefault(event.interface, []).append(float(current_bps))
            if len(self._baseline_learning_samples[event.interface]) > 4000:
                self._baseline_learning_samples[event.interface] = self._baseline_learning_samples[event.interface][-4000:]

            abs_threshold = self._rule_threshold("absolute_bandwidth_threshold", float(self.config.max_bytes_per_second))
            if (not learning_active) and current_bps > abs_threshold:
                alerts.append(
                    Alert(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        severity="high",
                        rule="absolute_bandwidth_threshold",
                        message=(
                            f"Interface {event.interface} exceeded max bandwidth rate"
                        ),
                        interface=event.interface,
                        observed_value=current_bps,
                        threshold=abs_threshold,
                        evidence={"interface": event.interface, "bytes_per_sec": current_bps, "learning_active": learning_active},
                    )
                )

            spike_threshold = max(
                baseline * self.config.spike_multiplier,
                self.config.minimum_spike_baseline_bps,
            )
            if current_bps > spike_threshold:
                alerts.append(
                    Alert(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        severity="medium",
                        rule="relative_spike_detection",
                        message=f"Interface {event.interface} traffic spiked above baseline",
                        interface=event.interface,
                        observed_value=current_bps,
                        threshold=spike_threshold,
                        evidence={"interface": event.interface, "baseline": baseline, "spike_multiplier": self.config.spike_multiplier},
                    )
                )

            # Keep a simple moving baseline that adapts slowly over time.
            self._baseline_per_interface[event.interface] = (baseline * 0.9) + (current_bps * 0.1)

        return self._finalize_alerts(alerts)

    def evaluate_connections(self, events: Iterable[ConnectionEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        now = time.monotonic()
        established_per_remote_ip = Counter(
            event.remote_ip
            for event in events
            if event.status in ("ESTABLISHED", "OBSERVED") and event.remote_ip
        )

        # Additional SIEM-style behavior baselines
        remote_ips_per_local: Dict[str, set] = {}
        remote_ports_per_pair: Dict[Tuple[str, str], set] = {}
        dns_count_per_local: Counter = Counter()
        unusual_service_port_count: Counter = Counter()

        for event in events:
            if not self._is_active_connection(event):
                continue
            local_ip = event.local_ip or "unknown"
            remote_ip = event.remote_ip or ""
            remote_port = int(event.remote_port or 0)

            if remote_ip:
                remote_ips_per_local.setdefault(local_ip, set()).add(remote_ip)
                remote_ports_per_pair.setdefault((local_ip, remote_ip), set()).add(remote_port)

            # track first-time local service exposures (potentially unusual)
            if int(event.local_port or 0) > 0:
                known = self._seen_local_service_ports.setdefault(local_ip, set())
                lport = int(event.local_port or 0)
                if lport not in known and len(known) >= 8 and lport not in _COMMON_EXTERNAL_SERVICE_PORTS:
                    ck = ("new_service_exposure", local_ip, lport)
                    if self._cooldown_allows(ck, now):
                        alerts.append(
                            Alert(
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                severity="medium",
                                rule="unusual_new_service_exposure",
                                message=f"Host {local_ip} exposed a new local service port {lport}",
                                interface=local_ip,
                                observed_value=float(lport),
                                threshold=float(lport),
                                evidence={"local_ip": local_ip, "new_port": lport, "known_count": len(known)},
                            )
                        )
                known.add(lport)

            # DNS burst indicator (queries/responses in high volume from one local host)
            if remote_port == 53 or int(event.local_port or 0) == 53:
                dns_count_per_local[local_ip] += 1

            # External uncommon service access indicator
            if (
                remote_ip
                and self._is_public_ip(remote_ip)
                and remote_port > 0
                and remote_port not in _COMMON_EXTERNAL_SERVICE_PORTS
            ):
                unusual_service_port_count[(local_ip, remote_port)] += 1

        for event in events:
            monitored_port = int(event.local_port or 0)
            is_high_risk = monitored_port in self.config.high_risk_ports
            is_suspicious = monitored_port in self.config.suspicious_ports
            if is_high_risk or is_suspicious:
                # Skip passive/listening sockets — these are just local services
                # sitting idle (e.g. Windows SMB on 445, RDP on 3389).
                if not self._is_active_connection(event):
                    continue
                # Suppress repeated alerts for the same (port, process) within
                # the cooldown window so that an ongoing connection doesn't spam.
                risk_level = "high" if is_high_risk else "medium"
                ck: Tuple = ("suspicious_port", monitored_port, event.process_name or "", risk_level)
                if not self._cooldown_allows(ck, now):
                    continue
                rule_name = "high_risk_service_port_activity" if is_high_risk else "suspicious_local_port_activity"
                threshold = float(monitored_port)
                alerts.append(
                    Alert(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        severity=risk_level,
                        rule=rule_name,
                        message=(
                            f"Observed network activity on monitored port {monitored_port} "
                            f"by process {event.process_name}"
                        ),
                        interface=event.local_ip or "unknown",
                        observed_value=float(monitored_port),
                        threshold=threshold,
                    )
                )

        # High outbound fanout from one local host to many remote hosts.
        for local_ip, remote_ips in remote_ips_per_local.items():
            remote_count = len(remote_ips)
            if remote_count > 60:
                ck = ("outbound_fanout", local_ip)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="high",
                            rule="outbound_remote_ip_fanout",
                            message=f"Host {local_ip} talked to unusually many remote IPs ({remote_count})",
                            interface=local_ip,
                            observed_value=float(remote_count),
                            threshold=60.0,
                            evidence={"local_ip": local_ip, "remote_ip_count": remote_count},
                        )
                    )

            # East-west lateral movement indicator: many private peers from one internal source.
            private_peers = [ip for ip in remote_ips if not self._is_public_ip(ip)]
            if len(private_peers) >= 15:
                ck = ("east_west_lateral", local_ip)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="medium",
                            rule="possible_east_west_lateral_movement",
                            message=f"Host {local_ip} contacted many internal peers ({len(private_peers)})",
                            interface=local_ip,
                            observed_value=float(len(private_peers)),
                            threshold=15.0,
                            evidence={"local_ip": local_ip, "internal_peer_count": len(private_peers)},
                        )
                    )

        # Potential scanning behavior: many destination ports to same remote.
        for (local_ip, remote_ip), ports in remote_ports_per_pair.items():
            port_count = len(ports)
            if port_count > 20:
                ck = ("remote_port_sweep", local_ip, remote_ip)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="high",
                            rule="possible_port_scan_or_service_sweep",
                            message=(
                                f"Host {local_ip} accessed many ports ({port_count}) on remote {remote_ip}"
                            ),
                            interface=local_ip,
                            observed_value=float(port_count),
                            threshold=20.0,
                        )
                    )

        # DNS burst signal frequently used for beaconing/tunneling triage.
        for local_ip, count in dns_count_per_local.items():
            if count > 80:
                ck = ("dns_burst", local_ip)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="medium",
                            rule="high_dns_activity",
                            message=f"Host {local_ip} generated high DNS activity ({count} flows)",
                            interface=local_ip,
                            observed_value=float(count),
                            threshold=80.0,
                        )
                    )

        # Repeated outbound connections to uncommon public service ports.
        for (local_ip, remote_port), count in unusual_service_port_count.items():
            if count > 15:
                ck = ("unusual_external_service_port", local_ip, remote_port)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="medium",
                            rule="unusual_external_service_port_usage",
                            message=(
                                f"Host {local_ip} made repeated outbound flows ({count}) "
                                f"to uncommon external service port {remote_port}"
                            ),
                            interface=local_ip,
                            observed_value=float(count),
                            threshold=15.0,
                        )
                    )

        for remote_ip, count in established_per_remote_ip.items():
            if count > self.config.max_established_connections_per_remote_ip:
                alerts.append(
                    Alert(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        severity="high",
                        rule="remote_ip_connection_fanout",
                        message=(
                            f"Remote host {remote_ip} has high established connection count "
                            f"({count})"
                        ),
                        interface=remote_ip,
                        observed_value=float(count),
                        threshold=float(self.config.max_established_connections_per_remote_ip),
                    )
                )

        return self._finalize_alerts(alerts)

    def evaluate_packet_events(self, events: Iterable[PacketEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        now = time.monotonic()

        # Source -> unique TCP destination ports where only SYN is present.
        syn_only_ports_per_source: Dict[str, Set[int]] = {}
        syn_packets_per_source: Counter = Counter()
        icmp_packets_per_source: Counter = Counter()
        dns_nxdomain_per_source: Counter = Counter()
        dns_slow_response_per_source: Counter = Counter()
        dns_long_query_per_source: Counter = Counter()
        tls_fp_destinations: Dict[Tuple[str, str], Set[str]] = {}

        for event in events:
            src_ip = (event.src_ip or "").strip()
            if not src_ip:
                continue

            protocol = (event.protocol or "").upper()
            if protocol == "TCP":
                flags = (event.tcp_flags or "").upper()
                # Scapy's string flags usually include 'S' for SYN; SYN+ACK has 'A'.
                if "S" in flags and "A" not in flags:
                    syn_packets_per_source[src_ip] += 1
                    dst_port = int(event.dst_port or 0)
                    if dst_port > 0:
                        syn_only_ports_per_source.setdefault(src_ip, set()).add(dst_port)
            elif protocol == "ICMP":
                icmp_packets_per_source[src_ip] += 1

            if (event.app_protocol or "").upper() == "DNS":
                if str(event.dns_rcode or "") == "3":
                    dns_nxdomain_per_source[src_ip] += 1
                rtt = event.dns_txn_rtt_ms
                if rtt is not None and float(rtt) >= 800.0:
                    dns_slow_response_per_source[src_ip] += 1
                if event.dns_query and len(str(event.dns_query)) >= 55:
                    dns_long_query_per_source[src_ip] += 1

            if (event.app_protocol or "").upper() == "TLS" and event.tls_fingerprint and event.dst_ip:
                tls_fp_destinations.setdefault((src_ip, event.tls_fingerprint), set()).add(event.dst_ip)

            # Track potential low-and-slow outbound beaconing candidates.
            if (
                (event.direction or "").lower() == "outbound"
                and protocol == "TCP"
                and event.dst_ip
                and int(event.dst_port or 0) > 0
                and int(event.payload_len or 0) <= 300
            ):
                bkey = (src_ip, event.dst_ip, int(event.dst_port or 0))
                obs = self._beacon_observations.setdefault(bkey, [])
                obs.append(now)
                ex = self._exfil_observations.setdefault(bkey, [])
                ex.append((now, int(event.payload_len or 0)))

        for src_ip, unique_ports in syn_only_ports_per_source.items():
            unique_count = len(unique_ports)
            if unique_count >= self.config.syn_scan_unique_ports_threshold:
                ck = ("syn_port_scan", src_ip)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="high",
                            rule="possible_syn_port_scan",
                            message=(
                                f"Source {src_ip} attempted SYN probes across {unique_count} destination ports"
                            ),
                            interface=src_ip,
                            observed_value=float(unique_count),
                            threshold=float(self.config.syn_scan_unique_ports_threshold),
                        )
                    )

        for src_ip, count in syn_packets_per_source.items():
            if count >= self.config.syn_flood_packets_per_source_threshold:
                ck = ("syn_flood", src_ip)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="high",
                            rule="possible_syn_flood",
                            message=f"Source {src_ip} generated unusually high SYN volume ({count})",
                            interface=src_ip,
                            observed_value=float(count),
                            threshold=float(self.config.syn_flood_packets_per_source_threshold),
                        )
                    )

        for src_ip, count in icmp_packets_per_source.items():
            if count >= self.config.icmp_flood_packets_per_source_threshold:
                ck = ("icmp_flood", src_ip)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="medium",
                            rule="possible_icmp_flood",
                            message=f"Source {src_ip} generated high ICMP packet volume ({count})",
                            interface=src_ip,
                            observed_value=float(count),
                            threshold=float(self.config.icmp_flood_packets_per_source_threshold),
                        )
                    )

        for src_ip, count in dns_nxdomain_per_source.items():
            if count >= 25:
                ck = ("dns_nxdomain_burst", src_ip)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="medium",
                            rule="high_dns_nxdomain_rate",
                            message=f"Source {src_ip} generated high NXDOMAIN volume ({count})",
                            interface=src_ip,
                            observed_value=float(count),
                            threshold=25.0,
                        )
                    )

        for src_ip, count in dns_slow_response_per_source.items():
            if count >= 20:
                ck = ("dns_slow_response_burst", src_ip)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="medium",
                            rule="high_dns_response_latency",
                            message=f"Source {src_ip} has many slow DNS transactions ({count})",
                            interface=src_ip,
                            observed_value=float(count),
                            threshold=20.0,
                            evidence={"source": src_ip, "slow_dns_count": count},
                        )
                    )

        for src_ip, count in dns_long_query_per_source.items():
            if count >= 25:
                ck = ("dns_tunnel_heuristic", src_ip)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="high",
                            rule="possible_dns_tunneling",
                            message=f"Source {src_ip} generated many long DNS queries ({count})",
                            interface=src_ip,
                            observed_value=float(count),
                            threshold=25.0,
                            evidence={"source": src_ip, "long_dns_query_count": count},
                        )
                    )

        for (src_ip, fp), dsts in tls_fp_destinations.items():
            dst_count = len(dsts)
            if dst_count >= int(self.config.tls_fingerprint_fanout_threshold):
                ck = ("tls_fp_fanout", src_ip, fp)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="medium",
                            rule="tls_fingerprint_high_fanout",
                            message=(
                                f"Source {src_ip} used one TLS fingerprint across many destinations ({dst_count})"
                            ),
                            interface=src_ip,
                            observed_value=float(dst_count),
                            threshold=float(self.config.tls_fingerprint_fanout_threshold),
                        )
                    )

        # Evaluate periodic outbound beacon-like timing over the configured sliding window.
        beacon_window = max(60, int(self.config.beacon_window_seconds))
        beacon_cutoff = now - float(beacon_window)
        min_obs = max(4, int(self.config.beacon_min_observations))
        min_interval = max(1.0, float(self.config.beacon_min_interval_seconds))
        max_interval = max(min_interval, float(self.config.beacon_max_interval_seconds))
        max_jitter_ratio = max(0.01, float(self.config.beacon_max_jitter_ratio))

        for bkey in list(self._beacon_observations.keys()):
            obs = [t for t in self._beacon_observations[bkey] if t >= beacon_cutoff]
            if len(obs) < 2:
                if obs:
                    self._beacon_observations[bkey] = obs
                else:
                    del self._beacon_observations[bkey]
                continue
            self._beacon_observations[bkey] = obs
            if len(obs) < min_obs:
                continue
            intervals = [obs[i] - obs[i - 1] for i in range(1, len(obs))]
            avg_interval = sum(intervals) / float(len(intervals))
            if avg_interval < min_interval or avg_interval > max_interval:
                continue
            variance = sum((x - avg_interval) ** 2 for x in intervals) / float(len(intervals))
            stddev = variance ** 0.5
            jitter_ratio = stddev / max(avg_interval, 1e-6)
            if jitter_ratio > max_jitter_ratio:
                continue

            src_ip, dst_ip, dst_port = bkey
            ck = ("periodic_beacon", src_ip, dst_ip, dst_port)
            if self._cooldown_allows(ck, now):
                alerts.append(
                    Alert(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        severity="high",
                        rule="possible_periodic_beaconing",
                        message=(
                            f"Possible beaconing from {src_ip} to {dst_ip}:{dst_port} "
                            f"(n={len(obs)}, interval~{avg_interval:.1f}s, jitter={jitter_ratio:.2f})"
                        ),
                        interface=src_ip,
                        observed_value=float(len(obs)),
                        threshold=float(min_obs),
                    )
                )

        # Long-lived low-volume outbound transfers (possible low-and-slow exfiltration)
        exfil_window = now - 1800.0
        for ekey in list(self._exfil_observations.keys()):
            rows = [(t, l) for t, l in self._exfil_observations[ekey] if t >= exfil_window]
            if len(rows) < 12:
                if rows:
                    self._exfil_observations[ekey] = rows
                else:
                    del self._exfil_observations[ekey]
                continue
            self._exfil_observations[ekey] = rows
            duration = rows[-1][0] - rows[0][0]
            avg_payload = (sum(l for _, l in rows) / float(len(rows))) if rows else 0.0
            if duration >= 1200.0 and avg_payload <= 120.0:
                src_ip, dst_ip, dst_port = ekey
                ck = ("low_volume_exfil", src_ip, dst_ip, dst_port)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="high",
                            rule="possible_low_volume_exfiltration",
                            message=(
                                f"Possible low-volume long-lived transfer from {src_ip} to {dst_ip}:{dst_port} "
                                f"(duration~{duration:.0f}s, avg_payload~{avg_payload:.1f} bytes)"
                            ),
                            interface=src_ip,
                            observed_value=float(avg_payload),
                            threshold=120.0,
                            evidence={"source": src_ip, "destination": dst_ip, "duration_seconds": duration, "avg_payload": round(avg_payload, 2)},
                        )
                    )

        return self._finalize_alerts(alerts)

    def evaluate_firewall_blocks(self, events: Iterable[FirewallBlockEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        now = time.monotonic()
        window_seconds = max(10, int(self.config.firewall_bruteforce_window_seconds))
        window_start = now - window_seconds
        sensitive_ports = set(int(p) for p in self.config.firewall_bruteforce_ports)

        for event in events:
            action = (event.action or "").upper()
            if action and action != "DROP":
                continue
            src_ip = (event.src_ip or "").strip()
            if not src_ip:
                continue
            dst_port = int(event.dst_port or 0)

            source_times = self._firewall_source_times.setdefault(src_ip, [])
            source_times.append(now)
            source_times[:] = [ts for ts in source_times if ts >= window_start]

            if dst_port in sensitive_ports:
                key = (src_ip, dst_port)
                attempt_times = self._firewall_attempt_times.setdefault(key, [])
                attempt_times.append(now)
                attempt_times[:] = [ts for ts in attempt_times if ts >= window_start]

        # Prune stale keys when no new events arrive for those sources.
        for key in list(self._firewall_attempt_times.keys()):
            times = [ts for ts in self._firewall_attempt_times[key] if ts >= window_start]
            if times:
                self._firewall_attempt_times[key] = times
            else:
                del self._firewall_attempt_times[key]
        for src_ip in list(self._firewall_source_times.keys()):
            times = [ts for ts in self._firewall_source_times[src_ip] if ts >= window_start]
            if times:
                self._firewall_source_times[src_ip] = times
            else:
                del self._firewall_source_times[src_ip]

        for (src_ip, dst_port), times in self._firewall_attempt_times.items():
            count = len(times)
            if count >= self.config.firewall_block_burst_threshold:
                ck = ("firewall_bruteforce", src_ip, dst_port)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="high",
                            rule="possible_bruteforce_or_service_attack",
                            message=(
                                f"Firewall blocked repeated attempts ({count}) from {src_ip} "
                                f"to service port {dst_port} in the last {window_seconds}s"
                            ),
                            interface=src_ip,
                            observed_value=float(count),
                            threshold=float(self.config.firewall_block_burst_threshold),
                        )
                    )

        for src_ip, times in self._firewall_source_times.items():
            count = len(times)
            threshold = int(self.config.firewall_block_burst_threshold * 2)
            if count >= threshold:
                ck = ("firewall_block_flood", src_ip)
                if self._cooldown_allows(ck, now):
                    alerts.append(
                        Alert(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity="medium",
                            rule="high_firewall_block_volume",
                            message=(
                                f"Firewall observed very high block volume ({count}) from {src_ip} "
                                f"in the last {window_seconds}s"
                            ),
                            interface=src_ip,
                            observed_value=float(count),
                            threshold=float(threshold),
                        )
                    )

        return self._finalize_alerts(alerts)


def alert_to_dict(alert: Alert) -> dict:
    return asdict(alert)
