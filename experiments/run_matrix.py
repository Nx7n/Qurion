import time
import json
import statistics
from collections import defaultdict
import os

from src.crypto.kem import generate_keypair, encapsulate, decapsulate
from src.crypto.signatures import generate_signing_keypair, sign, verify
from src.crypto.aead import encrypt, decrypt
from src.crypto.kdf import derive_key
from src.protocol.protected_avp import ProtectedAVP
from src.protocol.capability import QurionCapability
from src.protocol.transcript import TranscriptBuilder
from src.certificates.operator_cert import OperatorCertificate, KeyUsage
from src.diameter.avp_codec import DiameterMessage, AVPBuilder, AVP_AUTH_INFO
from src.diameter.peer_cache import PeerCapabilityCache
from src.telemetry.metrics import MetricsCollector

class BenchmarkMatrix:
    def __init__(self):
        self.results = defaultdict(list)
    
    def run_benchmark(self, name, func, iterations=100):
        latencies = []
        for _ in range(iterations):
            start = time.perf_counter_ns()
            func()
            latencies.append(time.perf_counter_ns() - start)
        self.results[name] = {
            "min": min(latencies),
            "max": max(latencies),
            "mean": statistics.mean(latencies),
            "median": statistics.median(latencies),
            "p95": statistics.quantiles(latencies, n=100)[94] if len(latencies) >= 100 else 0,
            "p99": statistics.quantiles(latencies, n=100)[98] if len(latencies) >= 100 else 0,
            "std": statistics.stdev(latencies) if len(latencies) > 1 else 0
        }

    def run_all(self):
        # E1
        def e1():
            msg = DiameterMessage(command_code=318, application_id=16777251, is_request=True)
            DiameterMessage.decode(msg.encode())
        self.run_benchmark("E1: Baseline Diameter", e1)
        
        # E2
        collector = MetricsCollector()
        collector.benchmark_crypto()
        
        # E3
        sk, pk = generate_keypair()
        sig_sk, sig_pk = generate_signing_keypair()
        def e3():
            avp = ProtectedAVP.create("sender", "recipient", b"av_data", pk, sig_sk)
            ser = avp.serialize()
            ProtectedAVP.deserialize(ser).open(sk, pk)
        self.run_benchmark("E3: Protected AV Exchange", e3, 10)
        
        # Output
        os.makedirs("experiments", exist_ok=True)
        with open("experiments/results.json", "w") as f:
            json.dump(self.results, f, indent=2)

if __name__ == "__main__":
    matrix = BenchmarkMatrix()
    matrix.run_all()
    print("Experiments complete. Results saved to experiments/results.json")
