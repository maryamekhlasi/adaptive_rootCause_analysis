import json
import glob
import os
import math
from collections import defaultdict
import statistics
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple
import numpy as np

class SpanInfo:
    def __init__(self, span_id, operation_name, start_time, duration, parent_span_id=None):
        self.span_id = span_id
        self.operation_name = operation_name
        self.start_time = start_time
        self.duration = duration
        self.end_time = start_time + duration
        self.parent_span_id = parent_span_id
        self.concurrent_spans = []
        self.childrens = []
        self.visited = False
        self.self_time = 0
        self.level = 0

class TraceAnalyzer:
    def __init__(self):
        self.all_traces = {}
        self.all_traces_info = {}
        self.turning_factor = 1.3  # n parameter from the formula

    def calculate_operation_statistics(self, operation_name: str) -> Tuple[float, float]:
        """Calculate mean and standard deviation of self time for an operation across all traces"""
        self_times = []
        for analysis in self.all_traces_info.values():
            for span in analysis['span_info'].values():
                if span['operation_name'] == operation_name:
                    self_times.append(span['self_time'])
        
        if not self_times:
            return 0.0, 0.0
        
        mean = np.mean(self_times)
        std_dev = np.std(self_times) if len(self_times) > 1 else 0
        return mean, std_dev

    def calculate_expected_latency(self, critical_path: List[Dict]) -> float:
        """Calculate expected latency using the formula Lmax = Σ(count_o * μ_self,o + n * σ_self,o)"""
        operation_counts = defaultdict(int)
        for span in critical_path:
            operation_counts[span['operation_name']] += 1

        total_latency = 0.0
        for op_name, count in operation_counts.items():
            mean_self_time, std_dev_self_time = self.calculate_operation_statistics(op_name)
            # Convert to milliseconds for consistency
            total_latency += (count * mean_self_time + self.turning_factor * std_dev_self_time) / 1000

        return total_latency

    def calculate_actual_latency(self, critical_path: List[Dict]) -> float:
        """Calculate actual latency based on self time of critical path"""
        total_self_time = sum(span['self_time'] for span in critical_path)
        return total_self_time / 1000  # Convert to milliseconds

    def get_critical_path_signature(self, critical_path):
        """Convert critical path to a string signature for comparison"""
        return ','.join(span['operation_name'] for span in critical_path)

    def group_similar_critical_paths(self):
        """Group traces with similar critical paths and calculate expected latency for each group"""
        groups = defaultdict(lambda: {'traces': [], 'critical_path': None, 'expected_latency': 0.0, 'actual_latencies': {}})
        
        for trace_name, analysis in self.all_traces_info.items():
            signature = self.get_critical_path_signature(analysis['critical_path'])
            groups[signature]['traces'].append(trace_name)
            groups[signature]['critical_path'] = analysis['critical_path']
            groups[signature]['expected_latency'] = self.calculate_expected_latency(analysis['critical_path'])
            groups[signature]['actual_latencies'][trace_name] = self.calculate_actual_latency(analysis['critical_path'])
        
        return groups

    def write_critical_paths_to_file(self, output_file="critical_paths.txt"):
        """Write critical paths to a file, grouping similar paths together and including expected and actual latencies"""
        groups = self.group_similar_critical_paths()
        
        with open(output_file, 'w') as f:
            for group_id, (signature, group_data) in enumerate(groups.items(), 1):
                f.write(f"group{group_id}: {','.join(group_data['traces'])}\n")
                f.write(f"critical_path: {signature}\n")
                f.write(f"expected_latency: {group_data['expected_latency']:.2f}ms\n")
                f.write("actual_latencies:\n")
                for trace_name, latency in group_data['actual_latencies'].items():
                    f.write(f"  {trace_name}: {latency:.2f}ms\n")
                f.write("\n")

    def read_json_file(self, file_path):
        """Read and parse a single JSON file."""
        print(f"Processing file: {file_path}")
        try:
            with open(file_path, 'r') as file:
                json_data = json.load(file)
                if 'data' not in json_data or not json_data['data']:
                    print(f"No 'data' found in JSON file: {file_path}")
                    return None
                return json_data
        except Exception as e:
            print(f"Error reading file {file_path}: {str(e)}")
            return None

    def read_all_traces(self, directory_path):
        """Read all JSON files from the specified directory."""
        json_files = glob.glob(os.path.join(directory_path, '*.json'))
        if not json_files:
            print("No JSON files found in the specified directory!")
            return {}

        for json_file_path in json_files:
            json_data = self.read_json_file(json_file_path)
            if json_data:
                output_file = os.path.splitext(os.path.basename(json_file_path))[0]
                self.all_traces[output_file] = json_data
                print(f"Processed file: {output_file}")

        return self.all_traces

    def extract_span_info(self, json_data):
        """Extract span information from JSON data."""
        span_info_dict = {}
        for span in json_data['data'][0]['spans']:
            span_id = span['spanID']
            operation_name = span['operationName']
            start_time = span['startTime']
            duration = span['duration']
            references = span.get('references', [])
            parent_span_id = next((ref['spanID'] for ref in references if ref.get('refType') == 'CHILD_OF'), None)

            span_info = SpanInfo(span_id, operation_name, start_time, duration, parent_span_id)
            span_info_dict[span_id] = vars(span_info)

        return span_info_dict

    def extract_children(self, span_info_dict):
        """Extract and organize children spans."""
        for span_id, span_info in span_info_dict.items():
            if span_info['parent_span_id']:
                child_info = (span_info['start_time'], span_id)
                span_info_dict[span_info['parent_span_id']]['childrens'].append(child_info)

        # Sort children by start time
        for span_info in span_info_dict.values():
            span_info['childrens'].sort(key=lambda x: x[0])

        return span_info_dict

    def identify_concurrent_spans(self, span_info_dict):
        """Identify spans that run concurrently."""
        for span_id, span_info in span_info_dict.items():
            children_span_ids = [child[1] for child in span_info['childrens']]
            for i, span_a_id in enumerate(children_span_ids):
                for span_b_id in children_span_ids[i + 1:]:
                    span_a = span_info_dict[span_a_id]
                    span_b = span_info_dict[span_b_id]

                    if (span_a['start_time'] < span_b['end_time'] and 
                        span_b['start_time'] < span_a['end_time']):
                        span_a['concurrent_spans'].append(span_b_id)
                        span_b['concurrent_spans'].append(span_a_id)

        return span_info_dict

    def merge_intervals(self, intervals):
        """Merge overlapping time intervals."""
        if not intervals:
            return []

        sorted_intervals = sorted(intervals, key=lambda x: x[0])
        merged = [sorted_intervals[0]]

        for current_start, current_end in sorted_intervals[1:]:
            last_merged_start, last_merged_end = merged[-1]
            if current_start <= last_merged_end:
                merged[-1] = (last_merged_start, max(last_merged_end, current_end))
            else:
                merged.append((current_start, current_end))

        return merged

    def calculate_self_time(self, span_info_dict):
        """Calculate self time for each span."""
        for span_id, span_info in span_info_dict.items():
            if span_info['childrens']:
                children = [span_info_dict[child[1]] for child in span_info['childrens']]
                merged_intervals = self.merge_intervals([
                    (child['start_time'], child['end_time']) 
                    for child in children
                ])
                covered_time = sum(end - start for start, end in merged_intervals)
                span_info['self_time'] = span_info['duration'] - covered_time
            else:
                span_info['self_time'] = span_info['duration']

        return span_info_dict

    def find_critical_path(self, span_info_dict):
        """Find the critical path through the trace."""
        def find_root():
            return next((span_id for span_id, info in span_info_dict.items() 
                        if info['parent_span_id'] is None), None)

        def dfs(span_id, path, level=0):
            span_info = span_info_dict[span_id]
            span_info['visited'] = True
            span_info['level'] = level
            path.append(span_info)

            if span_info['childrens']:
                children = [child[1] for child in span_info['childrens']]
                for child_id in children:
                    child_info = span_info_dict[child_id]
                    if not child_info['visited']:
                        if child_info['concurrent_spans']:
                            concurrent_spans = [(cid, span_info_dict[cid]['duration']) 
                                             for cid in child_info['concurrent_spans']]
                            concurrent_spans.append((child_id, child_info['duration']))
                            longest_span_id = max(concurrent_spans, key=lambda x: x[1])[0]
                            
                            for concurrent_id, _ in concurrent_spans:
                                span_info_dict[concurrent_id]['visited'] = True
                                span_info_dict[concurrent_id]['level'] = level + 1
                            
                            dfs(longest_span_id, path, level + 1)
                        else:
                            dfs(child_id, path, level + 1)

        root_span_id = find_root()
        if not root_span_id:
            return []

        critical_path = []
        dfs(root_span_id, critical_path)
        return critical_path

    def calculate_statistics(self, critical_path):
        """Calculate statistics for the critical path."""
        stats = defaultdict(lambda: {'count': 0, 'durations': [], 'self_times': []})
        total_self_time = 0
        total_duration = 0
        
        for span in critical_path:
            op_name = span['operation_name']
            stats[op_name]['count'] += 1
            stats[op_name]['durations'].append(span['duration'])
            stats[op_name]['self_times'].append(span['self_time'])
            total_self_time += span['self_time']
            total_duration += span['duration']

        results = {
            'total_self_time': total_self_time,
            'total_duration': total_duration,
            'operation_stats': {}
        }
        
        for op_name, data in stats.items():
            results['operation_stats'][op_name] = {
                'count': data['count'],
                'mean_duration': np.mean(data['durations']),
                'std_dev_duration': np.std(data['durations']) if len(data['durations']) > 1 else 0,
                'mean_self_time': np.mean(data['self_times']),
                'std_dev_self_time': np.std(data['self_times']) if len(data['self_times']) > 1 else 0
            }

        return results

    def analyze_trace(self, json_data):
        """Analyze a single trace."""
        span_info_dict = self.extract_span_info(json_data)
        span_info_dict = self.extract_children(span_info_dict)
        span_info_dict = self.identify_concurrent_spans(span_info_dict)
        span_info_dict = self.calculate_self_time(span_info_dict)
        critical_path = self.find_critical_path(span_info_dict)
        statistics = self.calculate_statistics(critical_path)
        
        return {
            'span_info': span_info_dict,
            'critical_path': critical_path,
            'statistics': statistics
        }

    def analyze_all_traces(self, directory_path):
        """Analyze all traces in the specified directory."""
        self.read_all_traces(directory_path)
        
        for trace_name, trace_data in self.all_traces.items():
            analysis_results = self.analyze_trace(trace_data)
            self.all_traces_info[trace_name] = analysis_results
            
        return self.all_traces_info

    def get_critical_path_durations(self):
        """Get a dictionary mapping file names to their critical path durations in milliseconds."""
        durations = {}
        for trace_name, analysis in self.all_traces_info.items():
            duration_ms = analysis['statistics']['total_duration'] / 1000
            durations[trace_name] = duration_ms
        return durations

def main():
    analyzer = TraceAnalyzer()
    directory_path = r"/home/maryam/Poly/Dorsal/traces/dataset/Second-Paper/anomaly-injected"
    results = analyzer.analyze_all_traces(directory_path)
    
    # Write critical paths to file
    analyzer.write_critical_paths_to_file("critical_paths.txt")
    print("\nCritical paths have been written to critical_paths.txt")
    
    # Get critical path durations
    durations = analyzer.get_critical_path_durations()
    print("\nCritical Path Durations by File:")
    for file_name, duration in durations.items():
        print(f"{file_name}: {duration:.2f} ms")
    
    # Print detailed analysis
    for trace_name, analysis in results.items():
        print(f"\nAnalysis for trace: {trace_name}")
        print("Critical Path Operations:")
        for span in analysis['critical_path']:
            print(f"  {span['operation_name']}: {span['duration']/1000:.2f}ms (self time: {span['self_time']/1000:.2f}ms)")
        print(f"\nTotal Duration of Critical Path: {analysis['statistics']['total_duration']/1000:.2f}ms")
        print(f"Total Self Time in Critical Path: {analysis['statistics']['total_self_time']/1000:.2f}ms")
        print("\nOperation Statistics:")
        for op_name, stats in analysis['statistics']['operation_stats'].items():
            print(f"  {op_name}:")
            print(f"    Count: {stats['count']}")
            print(f"    Mean Duration: {stats['mean_duration']/1000:.2f}ms")
            print(f"    Mean Self Time: {stats['mean_self_time']/1000:.2f}ms")

if __name__ == "__main__":
    main()
