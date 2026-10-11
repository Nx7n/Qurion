import json
import os
import glob

def collect_from_results(results_dir: str = 'results') -> dict:
    if not os.path.exists(results_dir):
        return {}
        
    collected = {}
    for filepath in glob.glob(f"{results_dir}/*.json"):
        with open(filepath, "r") as f:
            data = json.load(f)
            exp_id = data.get("experiment_id")
            if exp_id:
                if exp_id not in collected:
                    collected[exp_id] = []
                collected[exp_id].append(data)
    return collected

def aggregate_experiment(experiment_id: str, results_dir: str = 'results') -> dict:
    all_results = collect_from_results(results_dir)
    exp_results = all_results.get(experiment_id, [])
    
    if not exp_results:
        return {}
        
    # Example aggregation logic
    aggregated = {
        "experiment_id": experiment_id,
        "runs": len(exp_results),
        "mean_latency_ns_avg": sum(r["metrics"]["mean_latency_ns"] for r in exp_results) / len(exp_results) if exp_results else 0
    }
    return aggregated

def compare_experiments(exp_ids: list[str], results_dir: str = 'results') -> dict:
    comparison = {}
    for exp_id in exp_ids:
        comparison[exp_id] = aggregate_experiment(exp_id, results_dir)
    return comparison

def generate_summary_table(results_dir: str = 'results') -> str:
    all_results = collect_from_results(results_dir)
    
    table = "| Experiment | Runs | Avg Mean Latency (ns) |\n"
    table += "|------------|------|-----------------------|\n"
    
    for exp_id, runs in all_results.items():
        agg = aggregate_experiment(exp_id, results_dir)
        table += f"| {exp_id} | {agg['runs']} | {agg['mean_latency_ns_avg']} |\n"
        
    return table
