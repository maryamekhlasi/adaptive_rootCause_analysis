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
    



def main():
    analyzer = TraceAnalyzer()
    
    # Get current working directory
    current_dir = os.getcwd()
    
    # Create output directory if it doesn't exist
    output_dir = os.path.join(current_dir, "analysis_output")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Input directory path
    directory_path = r"/home/maryam/Poly/Dorsal/traces/dataset/article/article-3"
    results = analyzer.analyze_all_traces(directory_path)
    
    # Write critical paths to file in the output directory
    output_file = os.path.join(output_dir, "critical_paths.txt")
    abnormal_traces = analyzer.write_critical_paths_to_file(output_file)
    print(f"\nCritical paths have been written to {output_file}")
    

    # Create matrix for critical paths of abnormal traces
    output_file = os.path.join(output_dir, "critical_path_matrix.txt")
    critical_path_matrix = analyzer.create_partitioned_matrix_for_critical_paths(output_file)
    print(f"\nCritical path transition matrix has been written to {output_file}")
    print(f"Matrix dimensions: {critical_path_matrix['matrix'].shape}")
    print(f"Number of operations in critical paths: {len(critical_path_matrix['operations'])}")
    print(f"Number of abnormal traces: {len(critical_path_matrix['traces'])}")


    # Calculate and print transition probabilities for all traces
    #analyzer.print_transition_matrix("transition_matrix_all.txt")
    #print("\nTransition probabilities for all traces have been written to transition_matrix_all.txt")
    

    # Calculate and print transition probabilities for abnormal traces only
    output_file = os.path.join(output_dir, "transition_matrix_abnormal.txt")
    analyzer.print_transition_matrix(output_file, abnormal_only=True)
    print(f"\nTransition probabilities for abnormal traces have been written to {output_file}")
    
    # Create and write partitioned matrix for all traces
    output_file = os.path.join(output_dir, "transition_matrix_abnormal.txt")
    analyzer.create_partitioned_matrix(output_file)
    print(f"\nPartitioned transition matrix for all traces has been written to {output_file}")
    
    # Create and write partitioned matrix for abnormal traces only
    output_file = os.path.join(output_dir, "partitioned_matrix_abnormal.txt")
    analyzer.create_partitioned_matrix(output_file, abnormal_only=True)
    print(f"\nPartitioned transition matrix for abnormal traces has been written to {output_file}")
    
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
    
    # Calculate node ranks
    ranks = analyzer.calculate_node_ranks()
    print("\nNode ranks have been written to node_ranks.txt")
    
    # Print top 10 ranked nodes
    print("\nTop 10 Ranked Nodes:")
    for i, (node, rank) in enumerate(ranks.items()):
        if i >= 10:
            break
        print(f"{node}: {rank:.6f}")


        # Calculate PageRank with uniform preference
    ranks = analyzer.calculate_personalized_pagerank()
    print("\nPageRank scores have been written to personalized_pagerank.txt")
    
    # Print top 10 ranked nodes
    print("\nTop 10 Ranked Nodes:")
    for i, (node, rank) in enumerate(ranks.items()):
        if i >= 10:
            break
        print(f"{node}: {rank:.6f}")
    
    # Example: Calculate PageRank with preference for abnormal traces
    abnormal_preference = {}
    for trace in analyzer.abnormal_traces:
        abnormal_preference[trace['trace_name']] = 1.0
    
    ranks_abnormal = analyzer.calculate_personalized_pagerank(
        preference_vector=abnormal_preference,
        damping_factor=0.85,
        epsilon=1e-8
    )
    
    print("\nTop 10 Ranked Nodes (with preference for abnormal traces):")
    for i, (node, rank) in enumerate(ranks_abnormal.items()):
        if i >= 10:
            break
        print(f"{node}: {rank:.6f}")

if __name__ == "__main__":
    main() 
