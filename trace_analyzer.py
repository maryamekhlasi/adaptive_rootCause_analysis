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

    def create_partitioned_matrix(self, output_file="partitioned_matrix.txt", abnormal_only=False):
        """
        Create a partitioned matrix A = [[Aoo][Aot][Ato][0]] where:
        - Aoo: transitions between operations
        - Aot: transitions from operations to traces
        - Ato: transitions from traces to operations
        """
        # Get operation transitions (Aoo)
        operation_transitions = self.calculate_transition_probabilities(abnormal_only)
        
        # Get all unique operations and traces
        operations = set()
        traces = set()
        
        # If abnormal_only is True, only consider abnormal traces
        if abnormal_only:
            traces = {trace['trace_name'] for trace in self.abnormal_traces}
        else:
            traces = set(self.all_traces_info.keys())
        
        for analysis in self.all_traces_info.values():
            for span in analysis['critical_path']:
                operations.add(span['operation_name'])
        
        operations = sorted(list(operations))
        traces = sorted(list(traces))
        
        # Create Aot (Operations to Traces) and Ato (Traces to Operations)
        Aot = defaultdict(lambda: defaultdict(float))
        Ato = defaultdict(lambda: defaultdict(float))
        
        # Calculate Ato and Aot
        for trace_name, analysis in self.all_traces_info.items():
            # Skip if we're only looking at abnormal traces and this one isn't abnormal
            if abnormal_only:
                is_abnormal = False
                for abnormal_trace in self.abnormal_traces:
                    if abnormal_trace['trace_name'] == trace_name:
                        is_abnormal = True
                        break
                if not is_abnormal:
                    continue

            trace_operations = set()
            for span in analysis['critical_path']:
                op_name = span['operation_name']
                trace_operations.add(op_name)
                
            # For each operation in the trace, add transition from trace to operation
            for op_name in trace_operations:
                Ato[trace_name][op_name] = 1.0 / len(trace_operations)
                Aot[op_name][trace_name] = 1.0 / len(traces)  # Uniform distribution to traces
        
        # Write the partitioned matrix to file
        with open(output_file, 'w') as f:
            # Write header
            f.write("Partitioned Transition Matrix\n")
            if abnormal_only:
                f.write("(Abnormal Traces Only)\n")
            f.write("=" * 50 + "\n\n")
            
            # Write Aoo (Operation to Operation)
            f.write("Aoo (Operation to Operation transitions):\n")
            f.write("-" * 40 + "\n")
            for op1 in operations:
                for op2 in operations:
                    prob = operation_transitions.get(op1, {}).get(op2, 0.0)
                    if prob > 0:
                        f.write(f"{op1} -> {op2}: {prob:.3f}\n")
            f.write("\n")
            
            # Write Aot (Operation to Trace)
            f.write("Aot (Operation to Trace transitions):\n")
            f.write("-" * 40 + "\n")
            for op in operations:
                for trace in traces:
                    prob = Aot[op][trace]
                    if prob > 0:
                        f.write(f"{op} -> {trace}: {prob:.3f}\n")
            f.write("\n")
            
            # Write Ato (Trace to Operation)
            f.write("Ato (Trace to Operation transitions):\n")
            f.write("-" * 40 + "\n")
            for trace in traces:
                for op in operations:
                    prob = Ato[trace][op]
                    if prob > 0:
                        f.write(f"{trace} -> {op}: {prob:.3f}\n")
            f.write("\n")
            
            # Note about zero matrix
            f.write("Note: The bottom-right quadrant (Trace to Trace) is a zero matrix\n")

        # Return the matrices for potential further analysis
        return {
            'Aoo': operation_transitions,
            'Aot': dict(Aot),
            'Ato': dict(Ato)
        }

    def calculate_transition_probabilities(self, abnormal_only=False) -> Dict[str, Dict[str, float]]:
        """Calculate transition probabilities between operations in critical paths."""
        # Count transitions between operations
        transitions = defaultdict(lambda: defaultdict(int))
        outgoing_counts = defaultdict(int)

        # Analyze each trace's critical path
        for trace_name, analysis in self.all_traces_info.items():
            # Skip if we're only looking at abnormal traces and this one isn't abnormal
            if abnormal_only:
                is_abnormal = False
                for abnormal_trace in self.abnormal_traces:
                    if abnormal_trace['trace_name'] == trace_name:
                        is_abnormal = True
                        break
                if not is_abnormal:
                    continue

            critical_path = analysis['critical_path']
            
            # Look at consecutive pairs of operations in the critical path
            for i in range(len(critical_path) - 1):
                current_op = critical_path[i]['operation_name']
                next_op = critical_path[i + 1]['operation_name']
                
                transitions[current_op][next_op] += 1
                outgoing_counts[current_op] += 1

        # Calculate probabilities
        probabilities = {}
        for source_op in transitions:
            probabilities[source_op] = {}
            for target_op in transitions[source_op]:
                # Calculate probability as 1/O(s) where O(s) is the number of outgoing edges
                probabilities[source_op][target_op] = 1.0 / outgoing_counts[source_op]

        return probabilities

    def print_transition_matrix(self, output_file="transition_matrix.txt", abnormal_only=False):
        """Print the transition probability matrix to a file."""
        probabilities = self.calculate_transition_probabilities(abnormal_only)
        
        # Get all unique operation names
        operations = set()
        for source_op in probabilities:
            operations.add(source_op)
            for target_op in probabilities[source_op]:
                operations.add(target_op)
        operations = sorted(list(operations))

        with open(output_file, 'w') as f:
            # Write header
            f.write("Source Operation -> Target Operation: Probability\n")
            if abnormal_only:
                f.write("(Abnormal Traces Only)\n")
            f.write("-" * 50 + "\n\n")

            # Write probabilities
            for source_op in operations:
                if source_op in probabilities:
                    for target_op in operations:
                        prob = probabilities[source_op].get(target_op, 0.0)
                        if prob > 0:
                            f.write(f"{source_op} -> {target_op}: {prob:.3f}\n")
                    f.write("\n")

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
        abnormal_traces = []  # List to store abnormal trace information
        
        with open(output_file, 'w') as f:
            for group_id, (signature, group_data) in enumerate(groups.items(), 1):
                f.write(f"group{group_id}: {','.join(group_data['traces'])}\n")
                f.write(f"critical_path: {signature}\n")
                f.write(f"expected_latency: {group_data['expected_latency']:.2f}ms\n")
                f.write("actual_latencies:\n")
                
                # Check for abnormal traces in this group
                group_abnormal_traces = []
                for trace_name, latency in group_data['actual_latencies'].items():
                    is_abnormal = latency > group_data['expected_latency']
                    status = "ABNORMAL" if is_abnormal else "normal"
                    f.write(f"  {trace_name}: {latency:.2f}ms [{status}]\n")
                    
                    if is_abnormal:
                        group_abnormal_traces.append({
                            'trace_name': trace_name,
                            'expected_latency': group_data['expected_latency'],
                            'actual_latency': latency,
                            'difference': latency - group_data['expected_latency'],
                            'group_id': group_id,
                            'critical_path': signature
                        })
                
                if group_abnormal_traces:
                    f.write("\nAbnormal traces in this group:\n")
                    for trace in group_abnormal_traces:
                        f.write(f"  - {trace['trace_name']}: {trace['difference']:.2f}ms above expected\n")
                    abnormal_traces.extend(group_abnormal_traces)
                
                f.write("\n")
        
        # Write a summary of all abnormal traces at the end of the file
        if abnormal_traces:
            with open(output_file, 'a') as f:
                f.write("\n" + "="*50 + "\n")
                f.write("SUMMARY OF ABNORMAL TRACES\n")
                f.write("="*50 + "\n\n")
                f.write(f"Total number of abnormal traces: {len(abnormal_traces)}\n\n")
                
                # Sort abnormal traces by the difference between actual and expected latency
                abnormal_traces.sort(key=lambda x: x['difference'], reverse=True)
                
                for trace in abnormal_traces:
                    f.write(f"Trace: {trace['trace_name']}\n")
                    f.write(f"Group: {trace['group_id']}\n")
                    f.write(f"Critical Path: {trace['critical_path']}\n")
                    f.write(f"Expected Latency: {trace['expected_latency']:.2f}ms\n")
                    f.write(f"Actual Latency: {trace['actual_latency']:.2f}ms\n")
                    f.write(f"Excess Latency: {trace['difference']:.2f}ms\n")
                    f.write("-"*40 + "\n")
        
        # Store abnormal traces as a property of the class
        self.abnormal_traces = abnormal_traces
        return abnormal_traces

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

    def identify_high_latency_traces(self, output_file="high_latency_traces.txt"):
        """Identify and write traces where actual latency exceeds expected latency."""
        groups = self.group_similar_critical_paths()
        high_latency_traces = []
        
        for signature, group_data in groups.items():
            expected_latency = group_data['expected_latency']
            for trace_name, actual_latency in group_data['actual_latencies'].items():
                if actual_latency > expected_latency:
                    high_latency_traces.append({
                        'trace_name': trace_name,
                        'expected_latency': expected_latency,
                        'actual_latency': actual_latency,
                        'difference': actual_latency - expected_latency,
                        'critical_path': signature
                    })
        
        # Sort by the difference between actual and expected latency
        high_latency_traces.sort(key=lambda x: x['difference'], reverse=True)
        
        # Write results to file
        with open(output_file, 'w') as f:
            f.write("Traces with Actual Latency > Expected Latency\n")
            f.write("=" * 50 + "\n\n")
            
            if not high_latency_traces:
                f.write("No traces found where actual latency exceeds expected latency.\n")
            else:
                for trace in high_latency_traces:
                    f.write(f"Trace: {trace['trace_name']}\n")
                    f.write(f"Critical Path: {trace['critical_path']}\n")
                    f.write(f"Expected Latency: {trace['expected_latency']:.2f}ms\n")
                    f.write(f"Actual Latency: {trace['actual_latency']:.2f}ms\n")
                    f.write(f"Difference: {trace['difference']:.2f}ms\n")
                    f.write("-" * 50 + "\n\n")
        
        return high_latency_traces

    def calculate_node_ranks(self, damping_factor=0.85, epsilon=1e-8, max_iterations=100):
        """
        Calculate node ranks using the equation: v(q) = d·Av(q−1) + (1−d)·u
        with initial v = [Vo^T, Vt^T]^T where:
        - Vo = [1/No, 1/No, ...] (No is number of operations)
        - Vt = [1/Nt, 1/Nt, ...] (Nt is number of traces)
        
        The transition matrix A is calculated as [Aoo,Aot;Ato,0] where:
        Ast = 1/|O(s)| for t ∈ O(s), 0 otherwise
        """
        # Get all nodes (operations and traces)
        operations = set()
        traces = set(self.all_traces_info.keys())
        
        for analysis in self.all_traces_info.values():
            for span in analysis['critical_path']:
                operations.add(span['operation_name'])
        
        operations = sorted(list(operations))
        traces = sorted(list(traces))
        
        No = len(operations)  # Number of operations
        Nt = len(traces)     # Number of traces
        n = No + Nt         # Total number of nodes
        
        # Create the complete transition matrix A
        A = np.zeros((n, n))
        node_to_index = {node: i for i, node in enumerate(operations + traces)}
        
        # Calculate outgoing edges for each operation
        op_outgoing_edges = {}
        for op in operations:
            outgoing = set()
            # Count edges to other operations
            for analysis in self.all_traces_info.values():
                for i, span in enumerate(analysis['critical_path']):
                    if span['operation_name'] == op and i < len(analysis['critical_path']) - 1:
                        outgoing.add(analysis['critical_path'][i + 1]['operation_name'])
            # Count edges to traces
            for trace, analysis in self.all_traces_info.items():
                if any(span['operation_name'] == op for span in analysis['critical_path']):
                    outgoing.add(trace)
            op_outgoing_edges[op] = len(outgoing)
        
        # Calculate outgoing edges for each trace
        trace_outgoing_edges = {}
        for trace in traces:
            outgoing = set()
            analysis = self.all_traces_info[trace]
            for span in analysis['critical_path']:
                outgoing.add(span['operation_name'])
            trace_outgoing_edges[trace] = len(outgoing)
        
        # Fill Aoo (Operation to Operation)
        for op1 in operations:
            i = node_to_index[op1]
            num_outgoing = op_outgoing_edges[op1]
            if num_outgoing > 0:
                prob = 1.0 / num_outgoing
                for analysis in self.all_traces_info.values():
                    for j, span in enumerate(analysis['critical_path']):
                        if span['operation_name'] == op1 and j < len(analysis['critical_path']) - 1:
                            next_op = analysis['critical_path'][j + 1]['operation_name']
                            A[i][node_to_index[next_op]] = prob
        
        # Fill Aot (Operation to Trace)
        for op in operations:
            i = node_to_index[op]
            num_outgoing = op_outgoing_edges[op]
            if num_outgoing > 0:
                prob = 1.0 / num_outgoing
                for trace in traces:
                    if any(span['operation_name'] == op for span in self.all_traces_info[trace]['critical_path']):
                        A[i][node_to_index[trace]] = prob
        
        # Fill Ato (Trace to Operation)
        for trace in traces:
            i = node_to_index[trace]
            num_outgoing = trace_outgoing_edges[trace]
            if num_outgoing > 0:
                prob = 1.0 / num_outgoing
                for span in self.all_traces_info[trace]['critical_path']:
                    A[i][node_to_index[span['operation_name']]] = prob
        
        # Initialize vectors
        v = np.zeros(n)
        v[:No] = 1.0 / No  # Vo: Initial distribution for operations
        v[No:] = 1.0 / Nt  # Vt: Initial distribution for traces
        
        # Initialize uniform vector u with the same structure as v
        u = np.zeros(n)
        u[:No] = 1.0 / No
        u[No:] = 1.0 / Nt
        
        # Power iteration
        for iteration in range(max_iterations):
            v_next = damping_factor * np.dot(A, v) + (1 - damping_factor) * u
            
            # Check convergence
            if np.sum(np.abs(v_next - v)) < epsilon:
                v = v_next
                break
                
            v = v_next
        
        # Convert results to dictionary
        ranks = {}
        
        # Store operation ranks
        for op in operations:
            ranks[op] = v[node_to_index[op]]
        
        # Store trace ranks
        for trace in traces:
            ranks[trace] = v[node_to_index[trace]]
        
        # Sort ranks by value in descending order
        sorted_ranks = dict(sorted(ranks.items(), key=lambda x: x[1], reverse=True))
        
        # Write results to file
        with open("node_ranks.txt", "w") as f:
            f.write("Node Rankings\n")
            f.write("=" * 30 + "\n\n")
            f.write("Format: Node: Rank Score\n\n")
            
            # Write operation ranks
            f.write("Operations:\n")
            f.write("-" * 20 + "\n")
            for node, rank in sorted_ranks.items():
                if node in operations:
                    f.write(f"{node}: {rank:.6f}\n")
            f.write("\n")
            
            # Write trace ranks
            f.write("Traces:\n")
            f.write("-" * 20 + "\n")
            for node, rank in sorted_ranks.items():
                if node in traces:
                    f.write(f"{node}: {rank:.6f}\n")
            
            # Write initialization information
            f.write("\nInitialization Information:\n")
            f.write("-" * 20 + "\n")
            f.write(f"Number of operations (No): {No}\n")
            f.write(f"Number of traces (Nt): {Nt}\n")
            f.write(f"Initial value for operations (1/No): {1/No:.6f}\n")
            f.write(f"Initial value for traces (1/Nt): {1/Nt:.6f}\n")
        
        return sorted_ranks
    
    def create_partitioned_matrix(self, output_file="partitioned_matrix.txt", abnormal_only=False):
        """
        Create a partitioned matrix A = [[Aoo][Aot][Ato][0]] where:
        - Aoo: transitions between operations
        - Aot: transitions from operations to traces
        - Ato: transitions from traces to operations
        """
        # Get all unique operations and traces
        operations = set()
        traces = set()
        
        # If abnormal_only is True, only consider abnormal traces
        if abnormal_only:
            traces = {trace['trace_name'] for trace in self.abnormal_traces}
        else:
            traces = set(self.all_traces_info.keys())
        
        for analysis in self.all_traces_info.values():
            for span in analysis['critical_path']:
                operations.add(span['operation_name'])
        
        operations = sorted(list(operations))
        traces = sorted(list(traces))
        
        # Create numpy matrix for the complete transition matrix
        n = len(operations) + len(traces)
        A = np.zeros((n, n))
        node_to_index = {node: i for i, node in enumerate(operations + traces)}
        
        # Calculate Aoo (Operation to Operation)
        for op1 in operations:
            outgoing_ops = set()
            for analysis in self.all_traces_info.values():
                if abnormal_only and analysis not in self.abnormal_traces:
                    continue
                for i, span in enumerate(analysis['critical_path'][:-1]):
                    if span['operation_name'] == op1:
                        next_op = analysis['critical_path'][i + 1]['operation_name']
                        outgoing_ops.add(next_op)
            
            if outgoing_ops:
                prob = 1.0 / len(outgoing_ops)
                for op2 in outgoing_ops:
                    A[node_to_index[op1]][node_to_index[op2]] = prob
        
        # Calculate Aot (Operation to Trace)
        for op in operations:
            connected_traces = set()
            for trace_name, analysis in self.all_traces_info.items():
                if abnormal_only and trace_name not in traces:
                    continue
                if any(span['operation_name'] == op for span in analysis['critical_path']):
                    connected_traces.add(trace_name)
            
            if connected_traces:
                prob = 1.0 / len(connected_traces)
                for trace_name in connected_traces:
                    A[node_to_index[op]][node_to_index[trace_name]] = prob
        
        # Calculate Ato (Trace to Operation)
        for trace_name in traces:
            if trace_name in self.all_traces_info:
                ops_in_trace = set(span['operation_name'] for span in self.all_traces_info[trace_name]['critical_path'])
                if ops_in_trace:
                    prob = 1.0 / len(ops_in_trace)
                    for op in ops_in_trace:
                        A[node_to_index[trace_name]][node_to_index[op]] = prob
        
        # Write the matrix to file
        with open(output_file, 'w') as f:
            f.write("Partitioned Transition Matrix\n")
            if abnormal_only:
                f.write("(Abnormal Traces Only)\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("Matrix dimensions: {}x{}\n".format(n, n))
            f.write("Node order: " + ", ".join(operations + traces) + "\n\n")
            
            # Write the complete matrix
            f.write("Complete Matrix A:\n")
            np.savetxt(f, A, fmt='%.3f')
            f.write("\n")
            
            # Write individual quadrants for better readability
            f.write("Matrix Quadrants:\n")
            f.write("-" * 40 + "\n")
            
            No = len(operations)
            # Write Aoo
            f.write("\nAoo (Operation to Operation):\n")
            np.savetxt(f, A[:No, :No], fmt='%.3f')
            
            # Write Aot
            f.write("\nAot (Operation to Trace):\n")
            np.savetxt(f, A[:No, No:], fmt='%.3f')
            
            # Write Ato
            f.write("\nAto (Trace to Operation):\n")
            np.savetxt(f, A[No:, :No], fmt='%.3f')
        
        return {
            'matrix': A,
            'operations': operations,
            'traces': traces,
            'node_to_index': node_to_index
        }
    
    def create_partitioned_matrix_for_critical_paths(self, output_file="critical_path_matrix.txt"):
        """
        Create a partitioned matrix A = [[Aoo][Aot][Ato][0]] specifically for critical paths of abnormal traces.
        """
        # Get all unique operations from critical paths of abnormal traces
        operations = set()
        traces = set()
        
        # Get abnormal traces and their critical paths
        abnormal_trace_paths = {}
        for trace in self.abnormal_traces:
            trace_name = trace['trace_name']
            traces.add(trace_name)
            critical_path = self.all_traces_info[trace_name]['critical_path']
            abnormal_trace_paths[trace_name] = critical_path
            for span in critical_path:
                operations.add(span['operation_name'])
        
        operations = sorted(list(operations))
        traces = sorted(list(traces))
        
        # Create numpy matrix for the complete transition matrix
        n = len(operations) + len(traces)
        A = np.zeros((n, n))
        node_to_index = {node: i for i, node in enumerate(operations + traces)}
        
        # Calculate Aoo (Operation to Operation) based on critical path transitions
        for trace_name, critical_path in abnormal_trace_paths.items():
            for i in range(len(critical_path) - 1):
                current_op = critical_path[i]['operation_name']
                next_op = critical_path[i + 1]['operation_name']
                idx_current = node_to_index[current_op]
                idx_next = node_to_index[next_op]
                A[idx_current][idx_next] += 1
        
        # Normalize Aoo
        for i in range(len(operations)):
            row_sum = np.sum(A[i, :len(operations)])
            if row_sum > 0:
                A[i, :len(operations)] /= row_sum
        
        # Calculate Aot (Operation to Trace)
        for op in operations:
            op_idx = node_to_index[op]
            connected_traces = set()
            for trace_name, critical_path in abnormal_trace_paths.items():
                if any(span['operation_name'] == op for span in critical_path):
                    connected_traces.add(trace_name)
            
            if connected_traces:
                prob = 1.0 / len(connected_traces)
                for trace_name in connected_traces:
                    A[op_idx][node_to_index[trace_name]] = prob
        
        # Calculate Ato (Trace to Operation)
        for trace_name, critical_path in abnormal_trace_paths.items():
            trace_idx = node_to_index[trace_name]
            ops_in_path = set(span['operation_name'] for span in critical_path)
            if ops_in_path:
                prob = 1.0 / len(ops_in_path)
                for op in ops_in_path:
                    A[trace_idx][node_to_index[op]] = prob
        
        # Write the matrix to file
        with open(output_file, 'w') as f:
            f.write("Critical Path Transition Matrix for Abnormal Traces\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("Matrix Information:\n")
            f.write(f"Number of Operations: {len(operations)}\n")
            f.write(f"Number of Abnormal Traces: {len(traces)}\n")
            f.write(f"Total Matrix Size: {n}x{n}\n\n")
            
            f.write("Operations: " + ", ".join(operations) + "\n\n")
            f.write("Abnormal Traces: " + ", ".join(traces) + "\n\n")
            
            # Write the complete matrix
            f.write("Complete Matrix A:\n")
            np.savetxt(f, A, fmt='%.3f')
            f.write("\n")
            
            # Write individual quadrants
            No = len(operations)
            f.write("Matrix Quadrants:\n")
            f.write("-" * 40 + "\n")
            
            f.write("\nAoo (Operation to Operation transitions in critical paths):\n")
            np.savetxt(f, A[:No, :No], fmt='%.3f')
            
            f.write("\nAot (Operation to Trace transitions):\n")
            np.savetxt(f, A[:No, No:], fmt='%.3f')
            
            f.write("\nAto (Trace to Operation transitions):\n")
            np.savetxt(f, A[No:, :No], fmt='%.3f')
            
            # Write critical paths for reference
            f.write("\nCritical Paths:\n")
            f.write("-" * 40 + "\n")
            for trace_name, critical_path in abnormal_trace_paths.items():
                f.write(f"\n{trace_name}:\n")
                path_str = " -> ".join(span['operation_name'] for span in critical_path)
                f.write(f"{path_str}\n")
        
        return {
            'matrix': A,
            'operations': operations,
            'traces': traces,
            'node_to_index': node_to_index,
            'critical_paths': abnormal_trace_paths
        }
    

    def calculate_personalized_pagerank(self, damping_factor=0.85, epsilon=1e-8, max_iterations=100, preference_vector=None):
        """
        Calculate personalized PageRank scores using the iterative algorithm:
        v(q) = d·Av(q−1) + (1−d)·u
        
        Parameters:
        - damping_factor (d): typically 0.85
        - epsilon: convergence threshold
        - max_iterations: maximum number of iterations
        - preference_vector: custom preference vector u (if None, uses uniform distribution)
        
        Returns:
        - Dictionary mapping nodes to their PageRank scores
        """
        # Get all nodes (operations and traces)
        operations = set()
        traces = set(self.all_traces_info.keys())
        
        for analysis in self.all_traces_info.values():
            for span in analysis['critical_path']:
                operations.add(span['operation_name'])
        
        operations = sorted(list(operations))
        traces = sorted(list(traces))
        
        n = len(operations) + len(traces)  # Total number of nodes
        node_to_index = {node: i for i, node in enumerate(operations + traces)}
        index_to_node = {i: node for node, i in node_to_index.items()}
        
        # Create transition matrix A
        A = np.zeros((n, n))
        
        # Fill transition matrix A with probabilities
        # Operation to Operation transitions
        for op1 in operations:
            outgoing_ops = set()
            for analysis in self.all_traces_info.values():
                for i, span in enumerate(analysis['critical_path'][:-1]):
                    if span['operation_name'] == op1:
                        next_op = analysis['critical_path'][i + 1]['operation_name']
                        outgoing_ops.add(next_op)
            
            if outgoing_ops:
                prob = 1.0 / len(outgoing_ops)
                for op2 in outgoing_ops:
                    A[node_to_index[op1]][node_to_index[op2]] = prob
        
        # Operation to Trace transitions
        for op in operations:
            connected_traces = set()
            for trace_name, analysis in self.all_traces_info.items():
                if any(span['operation_name'] == op for span in analysis['critical_path']):
                    connected_traces.add(trace_name)
            
            if connected_traces:
                prob = 1.0 / len(connected_traces)
                for trace_name in connected_traces:
                    A[node_to_index[op]][node_to_index[trace_name]] = prob
        
        # Trace to Operation transitions
        for trace_name in traces:
            if trace_name in self.all_traces_info:
                ops_in_trace = set(span['operation_name'] 
                                for span in self.all_traces_info[trace_name]['critical_path'])
                if ops_in_trace:
                    prob = 1.0 / len(ops_in_trace)
                    for op in ops_in_trace:
                        A[node_to_index[trace_name]][node_to_index[op]] = prob
        
        # Initialize preference vector u (uniform if not provided)
        if preference_vector is None:
            u = np.ones(n) / n  # Uniform distribution
        else:
            u = np.array([preference_vector.get(node, 0.0) for node in operations + traces])
            if np.sum(u) == 0:
                raise ValueError("Preference vector cannot sum to zero")
            u = u / np.sum(u)  # Normalize to sum to 1
        
        # Initialize PageRank vector v
        v = np.ones(n) / n
        
        # Power iteration
        for iteration in range(max_iterations):
            v_next = damping_factor * np.dot(A, v) + (1 - damping_factor) * u
            
            # Check convergence
            if np.sum(np.abs(v_next - v)) < epsilon:
                v = v_next
                break
                
            v = v_next
        
        # Convert results to dictionary
        ranks = {node: v[idx] for node, idx in node_to_index.items()}
        sorted_ranks = dict(sorted(ranks.items(), key=lambda x: x[1], reverse=True))
        
        # Write results to file
        with open("personalized_pagerank.txt", "w") as f:
            f.write("Personalized PageRank Results\n")
            f.write("=" * 30 + "\n\n")
            
            f.write("Parameters:\n")
            f.write(f"Damping factor: {damping_factor}\n")
            f.write(f"Convergence threshold: {epsilon}\n")
            f.write(f"Number of nodes: {n}\n\n")
            
            # Write operation ranks
            f.write("Operation Rankings:\n")
            f.write("-" * 20 + "\n")
            for node, rank in sorted_ranks.items():
                if node in operations:
                    f.write(f"{node}: {rank:.6f}\n")
            f.write("\n")
            
            # Write trace ranks
            f.write("Trace Rankings:\n")
            f.write("-" * 20 + "\n")
            for node, rank in sorted_ranks.items():
                if node in traces:
                    f.write(f"{node}: {rank:.6f}\n")
            
            # Write preference vector
            f.write("\nPreference Vector:\n")
            f.write("-" * 20 + "\n")
            for i, value in enumerate(u):
                f.write(f"{index_to_node[i]}: {value:.6f}\n")
        
        return sorted_ranks
    






    def calculate_operation_coverage_scores(self):
        """
        Calculate operation coverage scores based on normal and abnormal trace coverage.
        
        Returns:
            Dictionary containing Oef, Oep, Onf, Onp scores for each operation
        """
        # Get all unique operations from critical paths
        operations = set()
        for analysis in self.all_traces_info.values():
            for span in analysis['critical_path']:
                operations.add(span['operation_name'])
        
        # Get sets of normal and abnormal trace names
        abnormal_trace_names = {trace['trace_name'] for trace in self.abnormal_traces}
        all_trace_names = set(self.all_traces_info.keys())
        normal_trace_names = all_trace_names - abnormal_trace_names
        
        # Calculate PageRank scores for all traces
        pagerank_scores = self.calculate_personalized_pagerank()
        
        # Calculate coverage statistics and scores for each operation
        coverage_scores = {}
        for operation in operations:
            # Initialize counters
            Nef = 0  # Number of abnormal traces covering the operation
            Nep = 0  # Number of normal traces covering the operation
            
            # Count coverage in abnormal and normal traces
            for trace_name, analysis in self.all_traces_info.items():
                op_in_trace = any(span['operation_name'] == operation 
                                for span in analysis['critical_path'])
                if op_in_trace:
                    if trace_name in abnormal_trace_names:
                        Nef += 1
                    else:
                        Nep += 1
            
            # Get total counts
            Nf = len(abnormal_trace_names)  # Total number of abnormal traces
            Np = len(normal_trace_names)    # Total number of normal traces
            # Get PageRank score for the operation
            F = pagerank_scores.get(operation, 0)  # Anomalous PageRank score
            P = 1 - F  # Normal PageRank score (complement of anomalous score)
            
            # Calculate the four scores
            Oef = F * Nef
            Oep = P * Nep
            Onf = F * (Nf - Nef)
            Onp = P * (Np - Nep)
            
            coverage_scores[operation] = {
                'Oef': Oef,
                'Oep': Oep,
                'Onf': Onf,
                'Onp': Onp,
                'coverage_stats': {
                    'abnormal_traces_covered': Nef,
                    'normal_traces_covered': Nep,
                    'total_abnormal_traces': Nf,
                    'total_normal_traces': Np,
                    'pagerank_score': F
                }
            }
        
        # Write results to file
        with open("operation_coverage_scores.txt", 'w') as f:
            f.write("Operation Coverage Analysis\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("Coverage Scores:\n")
            f.write("-" * 30 + "\n")
            for operation, scores in coverage_scores.items():
                f.write(f"\nOperation: {operation}\n")
                f.write(f"Oef (Abnormal coverage score): {scores['Oef']:.6f}\n")
                f.write(f"Oep (Normal coverage score): {scores['Oep']:.6f}\n")
                f.write(f"Onf (Abnormal non-coverage score): {scores['Onf']:.6f}\n")
                f.write(f"Onp (Normal non-coverage score): {scores['Onp']:.6f}\n")
                
                stats = scores['coverage_stats']
                f.write("\nCoverage Statistics:\n")
                f.write(f"- Abnormal traces covered: {stats['abnormal_traces_covered']}/{stats['total_abnormal_traces']}\n")
                f.write(f"- Normal traces covered: {stats['normal_traces_covered']}/{stats['total_normal_traces']}\n")
                f.write(f"- PageRank score: {stats['pagerank_score']:.6f}\n")
                f.write("-" * 30 + "\n")
        
        return coverage_scores


    def analyze_abnormal_coverage_ranking(self, output_file="abnormal_coverage_ranking.txt"):
        """
        Sort and analyze operations based on their abnormal coverage score (Oef).
        Returns sorted operations with their scores and detailed analysis.
        """
        # Calculate coverage scores if not already done
        coverage_scores = self.calculate_operation_coverage_scores()
        
        # Sort operations by Oef score
        sorted_operations = sorted(
            coverage_scores.items(),
            key=lambda x: x[1]['Oef'],
            reverse=True
        )
        
        # Calculate total scores for normalization
        total_Oef = sum(scores['Oef'] for _, scores in coverage_scores.items())
        total_Oep = sum(scores['Oep'] for _, scores in coverage_scores.items())
        
        # Write analysis to file
        with open(output_file, 'w') as f:
            f.write("Operation Ranking by Abnormal Coverage Score (Oef)\n")
            f.write("=" * 50 + "\n\n")
            
            # Write summary statistics
            f.write("Summary Statistics:\n")
            f.write("-" * 30 + "\n")
            f.write(f"Total number of operations: {len(coverage_scores)}\n")
            f.write(f"Total Oef score: {total_Oef:.6f}\n")
            f.write(f"Total Oep score: {total_Oep:.6f}\n\n")
            
            # Write detailed ranking
            f.write("Operation Ranking:\n")
            f.write("-" * 30 + "\n")
            
            for rank, (operation, scores) in enumerate(sorted_operations, 1):
                stats = scores['coverage_stats']
                normalized_Oef = scores['Oef'] / total_Oef if total_Oef > 0 else 0
                
                f.write(f"\nRank {rank}: {operation}\n")
                f.write(f"Abnormal Coverage Score (Oef): {scores['Oef']:.6f}\n")
                f.write(f"Normalized Oef: {normalized_Oef:.6f} ({normalized_Oef*100:.2f}%)\n")
                f.write(f"Normal Coverage Score (Oep): {scores['Oep']:.6f}\n")
                f.write(f"Coverage Ratio (Oef/Oep): {scores['Oef']/scores['Oep']:.6f} if scores['Oep'] > 0 else 'inf'\n")
                
                # Coverage statistics
                abnormal_coverage_pct = (stats['abnormal_traces_covered'] / stats['total_abnormal_traces'] * 100 
                                    if stats['total_abnormal_traces'] > 0 else 0)
                normal_coverage_pct = (stats['normal_traces_covered'] / stats['total_normal_traces'] * 100 
                                    if stats['total_normal_traces'] > 0 else 0)
                
                f.write("\nCoverage Statistics:\n")
                f.write(f"- Abnormal traces: {stats['abnormal_traces_covered']}/{stats['total_abnormal_traces']} ")
                f.write(f"({abnormal_coverage_pct:.2f}%)\n")
                f.write(f"- Normal traces: {stats['normal_traces_covered']}/{stats['total_normal_traces']} ")
                f.write(f"({normal_coverage_pct:.2f}%)\n")
                f.write(f"- PageRank score: {stats['pagerank_score']:.6f}\n")
                f.write("-" * 30 + "\n")

                
            # Write top N summary
            top_n_values = [5, 10, 20]
            f.write("\nTop-N Analysis:\n")
            f.write("-" * 30 + "\n")
                
            for n in top_n_values:
                top_n_Oef = sum(scores['Oef'] for _, scores in sorted_operations[:n])
                top_n_Oef_pct = (top_n_Oef / total_Oef * 100) if total_Oef > 0 else 0
                    
                f.write(f"\nTop {n} operations:\n")
                f.write(f"- Combined Oef score: {top_n_Oef:.6f}\n")
                f.write(f"- Percentage of total Oef: {top_n_Oef_pct:.2f}%\n")
                f.write(f"- Operations: {', '.join(op for op, _ in sorted_operations[:n])}\n")
            
            # Return sorted operations with their scores
        return sorted_operations



    def get_top_abnormal_operations(self, n=10):
        """
        Get the top N operations with highest abnormal coverage scores.
        
        Parameters:
            n (int): Number of top operations to return
        
        Returns:
            List of tuples (operation_name, scores)
        """
        sorted_operations = self.analyze_abnormal_coverage_ranking()
        return sorted_operations[:n]




    def find_lowest_level_operations(self, output_file="lowest_level_operations.txt"):
        """
        Find operations that appear at the lowest level in parent-child relationships
        within critical paths across all traces.
        """
        # Dictionary to store level information for each operation
        operation_levels = {}
        lowest_level_ops = {}

        # Analyze each trace's critical path
        for trace_name, analysis in self.all_traces_info.items():
            # Create a dictionary to track parent-child relationships
            parent_child_map = {}
            
            # Build parent-child relationships from span info
            for span_id, span_info in analysis['span_info'].items():
                if span_info['parent_span_id']:
                    parent_child_map[span_id] = span_info['parent_span_id']
            
            # Find operations in critical path and their levels
            for span in analysis['critical_path']:
                operation_name = span['operation_name']
                span_id = span['span_id']
                
                # Calculate level by traversing up the parent chain
                level = 0
                current_span_id = span_id
                while current_span_id in parent_child_map:
                    level += 1
                    current_span_id = parent_child_map[current_span_id]
                
                # Update operation levels
                if operation_name not in operation_levels:
                    operation_levels[operation_name] = {'max_level': level, 'occurrences': 1}
                else:
                    operation_levels[operation_name]['occurrences'] += 1
                    operation_levels[operation_name]['max_level'] = max(
                        operation_levels[operation_name]['max_level'], 
                        level
                    )
                
                # If this is an abnormal trace, track additional information
                if any(trace['trace_name'] == trace_name for trace in self.abnormal_traces):
                    if operation_name not in lowest_level_ops:
                        lowest_level_ops[operation_name] = {
                            'abnormal_occurrences': 1,
                            'normal_occurrences': 0,
                            'traces': [trace_name]
                        }
                    else:
                        lowest_level_ops[operation_name]['abnormal_occurrences'] += 1
                        lowest_level_ops[operation_name]['traces'].append(trace_name)
                else:
                    if operation_name not in lowest_level_ops:
                        lowest_level_ops[operation_name] = {
                            'abnormal_occurrences': 0,
                            'normal_occurrences': 1,
                            'traces': [trace_name]
                        }
                    else:
                        lowest_level_ops[operation_name]['normal_occurrences'] += 1
                        lowest_level_ops[operation_name]['traces'].append(trace_name)

            # Find operations that appear at the lowest level
        max_level = max(info['max_level'] for info in operation_levels.values())
        lowest_level_operations = {
            op: info for op, info in operation_levels.items() 
            if info['max_level'] == max_level
        }

        # Write analysis to file
        with open(output_file, 'w') as f:
            f.write("Lowest Level Operations Analysis\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Maximum depth level found: {max_level}\n\n")
            
            f.write("Operations at the lowest level:\n")
            f.write("-" * 30 + "\n")
            
            # Sort operations by number of occurrences
            sorted_ops = sorted(
                lowest_level_operations.items(),
                key=lambda x: x[1]['occurrences'],
                reverse=True
            )
            
            for op_name, info in sorted_ops:
                f.write(f"\nOperation: {op_name}\n")
                f.write(f"Occurrences: {info['occurrences']}\n")
                
                if op_name in lowest_level_ops:
                    op_stats = lowest_level_ops[op_name]
                    total_traces = op_stats['abnormal_occurrences'] + op_stats['normal_occurrences']
                    abnormal_percentage = (op_stats['abnormal_occurrences'] / total_traces * 100 
                                        if total_traces > 0 else 0)
                    
                    f.write(f"Abnormal trace occurrences: {op_stats['abnormal_occurrences']}\n")
                    f.write(f"Normal trace occurrences: {op_stats['normal_occurrences']}\n")
                    f.write(f"Percentage in abnormal traces: {abnormal_percentage:.2f}%\n")
                    f.write("Traces containing this operation:\n")
                    for trace in op_stats['traces']:
                        trace_type = "ABNORMAL" if any(t['trace_name'] == trace 
                                                    for t in self.abnormal_traces) else "normal"
                        f.write(f"- {trace} [{trace_type}]\n")
                
                f.write("-" * 30 + "\n")
                
            # Write summary statistics
            f.write("\nSummary Statistics:\n")
            f.write("-" * 30 + "\n")
            f.write(f"Total number of lowest level operations: {len(lowest_level_operations)}\n")
            total_occurrences = sum(info['occurrences'] for info in lowest_level_operations.values())
            f.write(f"Total occurrences of lowest level operations: {total_occurrences}\n")
            
            # Calculate percentage of abnormal traces containing each operation
            if self.abnormal_traces:
                f.write("\nAbnormal Trace Coverage:\n")
                for op_name in lowest_level_operations:
                    if op_name in lowest_level_ops:
                        abnormal_count = lowest_level_ops[op_name]['abnormal_occurrences']
                        coverage_pct = (abnormal_count / len(self.abnormal_traces) * 100)
                        f.write(f"{op_name}: {coverage_pct:.2f}% of abnormal traces\n")

        return {
            'max_level': max_level,
            'lowest_level_operations': lowest_level_operations,
            'operation_stats': lowest_level_ops
        }

def main():
    analyzer = TraceAnalyzer()
    
    # Get current working directory
    current_dir = os.getcwd()
    
    # Create output directory if it doesn't exist
    output_dir = os.path.join(current_dir, "analysis_output")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Define a single output file for all analysis results
    output_file = os.path.join(output_dir, "trace_analysis_results.txt")
    
    # Input directory path
    directory_path = r"/home/maryam/Poly/Dorsal/traces/dataset/article/article-3"
    results = analyzer.analyze_all_traces(directory_path)
    
    # Write all analysis results to the same file
    with open(output_file, 'w') as f:
        # Critical paths analysis
        f.write("CRITICAL PATHS ANALYSIS\n")
        f.write("=" * 50 + "\n\n")
        abnormal_traces = analyzer.write_critical_paths_to_file(output_file)
        
        # Critical path matrix
        f.write("\n\nCRITICAL PATH TRANSITION MATRIX\n")
        f.write("=" * 50 + "\n\n")
        critical_path_matrix = analyzer.create_partitioned_matrix_for_critical_paths(output_file)
        print(f"Matrix dimensions: {critical_path_matrix['matrix'].shape}")
        print(f"Number of operations in critical paths: {len(critical_path_matrix['operations'])}")
        print(f"Number of abnormal traces: {len(critical_path_matrix['traces'])}")
        
        # Transition probabilities for abnormal traces
        f.write("\n\nTRANSITION PROBABILITIES (ABNORMAL TRACES)\n")
        f.write("=" * 50 + "\n\n")
        analyzer.print_transition_matrix(output_file, abnormal_only=True)
        
        # Partitioned matrix for all traces
        f.write("\n\nPARTITIONED MATRIX (ALL TRACES)\n")
        f.write("=" * 50 + "\n\n")
        analyzer.create_partitioned_matrix(output_file)
        
        # Partitioned matrix for abnormal traces
        f.write("\n\nPARTITIONED MATRIX (ABNORMAL TRACES)\n")
        f.write("=" * 50 + "\n\n")
        analyzer.create_partitioned_matrix(output_file, abnormal_only=True)
        
        # Get critical path durations
        f.write("\n\nCRITICAL PATH DURATIONS\n")
        f.write("=" * 50 + "\n\n")
        durations = analyzer.get_critical_path_durations()
        for file_name, duration in durations.items():
            f.write(f"{file_name}: {duration:.2f} ms\n")
        
        # Print detailed analysis
        f.write("\n\nDETAILED TRACE ANALYSIS\n")
        f.write("=" * 50 + "\n\n")
        for trace_name, analysis in results.items():
            f.write(f"\nAnalysis for trace: {trace_name}\n")
            f.write("Critical Path Operations:\n")
            for span in analysis['critical_path']:
                f.write(f"  {span['operation_name']}: {span['duration']/1000:.2f}ms (self time: {span['self_time']/1000:.2f}ms)\n")
            f.write(f"\nTotal Duration of Critical Path: {analysis['statistics']['total_duration']/1000:.2f}ms\n")
            f.write(f"Total Self Time in Critical Path: {analysis['statistics']['total_self_time']/1000:.2f}ms\n")
            f.write("\nOperation Statistics:\n")
            for op_name, stats in analysis['statistics']['operation_stats'].items():
                f.write(f"  {op_name}:\n")
                f.write(f"    Count: {stats['count']}\n")
                f.write(f"    Mean Duration: {stats['mean_duration']/1000:.2f}ms\n")
                f.write(f"    Mean Self Time: {stats['mean_self_time']/1000:.2f}ms\n")
        
        # Node ranks
        f.write("\n\nNODE RANKS\n")
        f.write("=" * 50 + "\n\n")
        ranks = analyzer.calculate_node_ranks()
        for node, rank in list(ranks.items())[:10]:
            f.write(f"{node}: {rank:.6f}\n")
        
        # PageRank analysis
        f.write("\n\nPAGERANK ANALYSIS\n")
        f.write("=" * 50 + "\n\n")
        ranks = analyzer.calculate_personalized_pagerank()
        f.write("Top 10 Ranked Nodes:\n")
        for node, rank in list(ranks.items())[:10]:
            f.write(f"{node}: {rank:.6f}\n")
        
        # PageRank with preference for abnormal traces
        abnormal_preference = {}
        for trace in analyzer.abnormal_traces:
            abnormal_preference[trace['trace_name']] = 1.0
        
        ranks_abnormal = analyzer.calculate_personalized_pagerank(
            preference_vector=abnormal_preference,
            damping_factor=0.85,
            epsilon=1e-8
        )
        
        f.write("\nTop 10 Ranked Nodes (with preference for abnormal traces):\n")
        for node, rank in list(ranks_abnormal.items())[:10]:
            f.write(f"{node}: {rank:.6f}\n")
        
        # Operation coverage scores
        f.write("\n\nOPERATION COVERAGE SCORES\n")
        f.write("=" * 50 + "\n\n")
        coverage_scores = analyzer.calculate_operation_coverage_scores()
        sorted_ops = sorted(coverage_scores.items(), 
                          key=lambda x: x[1]['Oef'], 
                          reverse=True)
        for operation, scores in sorted_ops[:10]:
            f.write(f"{operation}: {scores['Oef']:.6f}\n")
        
        # Abnormal coverage ranking
        f.write("\n\nABNORMAL COVERAGE RANKING\n")
        f.write("=" * 50 + "\n\n")
        sorted_operations = analyzer.analyze_abnormal_coverage_ranking()
        for rank, (operation, scores) in enumerate(sorted_operations[:10], 1):
            f.write(f"{rank}. {operation}: {scores['Oef']:.6f}\n")
            f.write(f"   Abnormal traces covered: {scores['coverage_stats']['abnormal_traces_covered']}/")
            f.write(f"{scores['coverage_stats']['total_abnormal_traces']}\n")
        
        # Lowest level operations
        f.write("\n\nLOWEST LEVEL OPERATIONS\n")
        f.write("=" * 50 + "\n\n")
        lowest_level_results = analyzer.find_lowest_level_operations()
        f.write(f"Found {len(lowest_level_results['lowest_level_operations'])} operations at level {lowest_level_results['max_level']}:\n")
        for op_name, info in lowest_level_results['lowest_level_operations'].items():
            f.write(f"- {op_name}: {info['occurrences']} occurrences\n")

    print(f"\nAll analysis results have been written to {output_file}")

if __name__ == "__main__":
    main()
