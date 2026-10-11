import os
import json
import csv
import math

def load_results(results_dir: str = 'results') -> dict:
    from experiments.collect_metrics import collect_from_results
    return collect_from_results(results_dir)

def compute_statistics(data: list[float]) -> dict:
    if not data:
        return {}
    
    data = sorted(data)
    n = len(data)
    mean = sum(data) / n
    std = math.sqrt(sum((x - mean) ** 2 for x in data) / n)
    
    def percentile(p):
        k = (n - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return data[int(k)]
        d0 = data[int(f)] * (c - k)
        d1 = data[int(c)] * (k - f)
        return d0 + d1

    return {
        "mean": mean,
        "median": percentile(0.5),
        "p95": percentile(0.95),
        "p99": percentile(0.99),
        "std": std,
        "min": data[0],
        "max": data[-1]
    }

def compare_baseline(baseline: dict, protected: dict) -> dict:
    # Example logic
    b_lat = baseline.get("mean_latency_ns_avg", 1)
    p_lat = protected.get("mean_latency_ns_avg", 1)
    
    return {
        "overhead_ns": p_lat - b_lat,
        "overhead_ratio": p_lat / b_lat if b_lat else 0
    }

def generate_latex_table(results: dict, output_file: str):
    with open(output_file, "w") as f:
        f.write("\\begin{tabular}{|c|c|c|}\n")
        f.write("\\hline\n")
        f.write("Experiment & Runs & Avg Mean Latency (ns) \\\\\n")
        f.write("\\hline\n")
        for exp_id, runs in results.items():
            f.write(f"{exp_id} & {len(runs)} & {runs[0]['metrics']['mean_latency_ns']} \\\\\n")
        f.write("\\hline\n")
        f.write("\\end{tabular}\n")

def generate_csv_summary(results: dict, output_file: str):
    with open(output_file, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Experiment", "Runs", "Avg Mean Latency (ns)"])
        for exp_id, runs in results.items():
            writer.writerow([exp_id, len(runs), runs[0]["metrics"]["mean_latency_ns"]])

def main():
    results = load_results()
    generate_csv_summary(results, "results_summary.csv")
    print("Analysis complete. Generated results_summary.csv")

if __name__ == "__main__":
    main()
