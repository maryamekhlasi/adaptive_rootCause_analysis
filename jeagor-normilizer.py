import json
import os

def fix_jaeger_trace(file_path, output_dir):
    """Fix issues in a Jaeger JSON trace file and save it to another directory."""
    with open(file_path, "r") as f:
        try:
            trace_data = json.load(f)
        except json.JSONDecodeError:
            print(f"Skipping {file_path}: Invalid JSON format")
            return None

    # Convert timestamps from nanoseconds to microseconds
    for trace in trace_data.get("data", []):
        for span in trace.get("spans", []):
            if "startTime" in span:
                span["startTime"] //= 1000  # Convert nanoseconds to microseconds
            
            if "logs" in span:
                for log in span["logs"]:
                    if "timestamp" in log:
                        log["timestamp"] //= 1000

    # Collect all process IDs used in spans
    process_ids = {span["processID"] for trace in trace_data.get("data", []) for span in trace.get("spans", [])}

    # Ensure the "processes" section exists and includes all process IDs
    if "processes" not in trace_data:
        trace_data["processes"] = {}

    for pid in process_ids:
        if pid not in trace_data["processes"]:
            trace_data["processes"][pid] = {
                "serviceName": "FixedService",
                "tags": [
                    {"key": "client-uuid", "type": "string", "value": "fixed-uuid"},
                    {"key": "hostname", "type": "string", "value": "fixed-host"},
                    {"key": "ip", "type": "string", "value": "127.0.0.1"},
                    {"key": "jaeger.version", "type": "string", "value": "Go-2.30.0"},
                ],
            }

    # Ensure internal.span.format is Jaeger-compatible
    for trace in trace_data.get("data", []):
        for span in trace.get("spans", []):
            for tag in span.get("tags", []):
                if tag.get("key") == "internal.span.format":
                    tag["value"] = "jaeger.thrift"  # Convert format

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Save the corrected JSON file in the output directory
    filename = os.path.basename(file_path).replace(".json", "_fixed.json")
    fixed_file_path = os.path.join(output_dir, filename)

    with open(fixed_file_path, "w") as f:
        json.dump(trace_data, f, indent=4)

    print(f"Fixed file saved: {fixed_file_path}")
    return fixed_file_path


def fix_all_traces(input_dir, output_dir):
    """Fix all Jaeger JSON trace files from input directory and save them to output directory."""
    if not os.path.exists(input_dir):
        print(f"Input directory not found: {input_dir}")
        return

    json_files = [f for f in os.listdir(input_dir) if f.endswith(".json")]

    if not json_files:
        print("No valid JSON trace files found in the input directory.")
        return

    print(f"Found {len(json_files)} JSON trace files in {input_dir}. Processing...")

    fixed_files = []
    for filename in json_files:
        file_path = os.path.join(input_dir, filename)
        fixed_file = fix_jaeger_trace(file_path, output_dir)
        if fixed_file:
            fixed_files.append(fixed_file)

    print(f"Fixed {len(fixed_files)} trace files successfully. Saved to {output_dir}.")

# Change these paths to your actual input and output directories
input_directory = "/home/maryam/Poly/Dorsal/traces/dataset/nezha/8276375/yuxiaoba/Nezha-v0.1/yuxiaoba-Nezha-b0dc1c4/rca_data/2022-08-22/trace-out_3"
output_directory = "/home/maryam/Poly/Dorsal/traces/dataset/nezha/8276375/yuxiaoba/Nezha-v0.1/yuxiaoba-Nezha-b0dc1c4/rca_data/2022-08-22/trace-out_3/fixed_jaeger_traces"

fix_all_traces(input_directory, output_directory)
