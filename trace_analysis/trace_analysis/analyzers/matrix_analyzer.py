from typing import Dict, List, Set, Union, TextIO, Optional
import numpy as np
from collections import defaultdict
import os


class MatrixAnalyzer:
    @staticmethod
    def create_partitioned_matrix(operations: Set[str], 
                                traces: Set[str], 
                                trace_info: Dict,
                                output_file: Optional[Union[str, TextIO]] = None) -> Dict:
        """
        Create a partitioned matrix A = [[Aoo][Aot][Ato][0]]
        
        Args:
            operations: Set of operation names
            traces: Set of trace IDs
            trace_info: Dictionary containing trace analysis information
            output_file: Either a file path (str) or a file object
        """
        operations = sorted(list(operations))
        traces = sorted(list(traces))
        n = len(operations) + len(traces)
        A = np.zeros((n, n))
        node_to_index = {node: i for i, node in enumerate(operations + traces)}

        # Calculate matrix values...
        # [Your existing matrix calculation code here]

        # Write matrix to file if specified
        if output_file is not None:
            MatrixAnalyzer._write_matrix_to_file(
                A, operations, traces, node_to_index, 
                output_file, False
            )

        return {
            'matrix': A,
            'operations': operations,
            'traces': traces,
            'node_to_index': node_to_index
        }

    @staticmethod
    def create_critical_path_matrix(operations: Set[str], 
                                  abnormal_traces: Dict, 
                                  trace_info: Dict,
                                  output_file: str = None) -> Dict:
        """
        Create a partitioned matrix specifically for critical paths of abnormal traces.
        
        Args:
            operations: Set of operation names
            abnormal_traces: Dictionary of abnormal traces
            trace_info: Dictionary containing trace analysis information
            output_file: Path to output file (optional)
            
        Returns:
            Dictionary containing matrix and related information
        """
        operations = sorted(list(operations))
        traces = sorted(list(abnormal_traces.keys()))
        
        n = len(operations) + len(traces)
        A = np.zeros((n, n))
        node_to_index = {node: i for i, node in enumerate(operations + traces)}

        # Calculate Aoo based on critical path transitions
        for trace_name, trace_data in abnormal_traces.items():
            critical_path = trace_info[trace_name]['critical_path']
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
            for trace_name in traces:
                critical_path = trace_info[trace_name]['critical_path']
                if any(span['operation_name'] == op for span in critical_path):
                    connected_traces.add(trace_name)
            
            if connected_traces:
                prob = 1.0 / len(connected_traces)
                for trace_name in connected_traces:
                    A[op_idx][node_to_index[trace_name]] = prob

        # Calculate Ato (Trace to Operation)
        for trace_name in traces:
            trace_idx = node_to_index[trace_name]
            critical_path = trace_info[trace_name]['critical_path']
            ops_in_path = set(span['operation_name'] for span in critical_path)
            
            if ops_in_path:
                prob = 1.0 / len(ops_in_path)
                for op in ops_in_path:
                    A[trace_idx][node_to_index[op]] = prob

        # Write matrix to file if specified
        if output_file:
            MatrixAnalyzer._write_matrix_to_file(A, operations, traces, node_to_index, 
                                               output_file, True, is_critical_path=True)

        return {
            'matrix': A,
            'operations': operations,
            'traces': traces,
            'node_to_index': node_to_index,
            'critical_paths': {t: trace_info[t]['critical_path'] for t in traces}
        }

    # ... (keep all the imports and the beginning of the class)

    @staticmethod
    def _write_matrix_to_file(matrix: np.ndarray,
                             operations: List[str],
                             traces: List[str],
                             node_to_index: Dict,
                             output_file: Union[str, TextIO],
                             is_abnormal: bool,
                             is_critical_path: bool = False) -> None:
        """
        Write the matrix analysis to a file.
        
        Args:
            matrix: The transition matrix
            operations: List of operation names
            traces: List of trace IDs
            node_to_index: Mapping of nodes to matrix indices
            output_file: Either a file path (str) or a file object
            is_abnormal: Whether this is for abnormal traces only
            is_critical_path: Whether this is a critical path matrix
        """
        def write_content(f):
            # Write header
            header = "Critical Path " if is_critical_path else ""
            header += "Transition Matrix"
            if is_abnormal:
                header += " for Abnormal Traces"
            f.write(f"{header}\n")
            f.write("=" * 50 + "\n\n")

            # Write matrix information
            f.write("Matrix Information:\n")
            f.write(f"Number of Operations: {len(operations)}\n")
            f.write(f"Number of {'Abnormal ' if is_abnormal else ''}Traces: {len(traces)}\n")
            f.write(f"Total Matrix Size: {matrix.shape[0]}x{matrix.shape[1]}\n\n")

            f.write("Operations: " + ", ".join(operations) + "\n\n")
            f.write(f"{'Abnormal ' if is_abnormal else ''}Traces: " + ", ".join(traces) + "\n\n")

            # Write complete matrix
            f.write("Complete Matrix A:\n")
            np.savetxt(f, matrix, fmt='%.3f')
            f.write("\n")

            # Write individual quadrants
            No = len(operations)
            f.write("Matrix Quadrants:\n")
            f.write("-" * 40 + "\n")

            f.write("\nAoo (Operation to Operation transitions):\n")
            np.savetxt(f, matrix[:No, :No], fmt='%.3f')

            f.write("\nAot (Operation to Trace transitions):\n")
            np.savetxt(f, matrix[:No, No:], fmt='%.3f')

            f.write("\nAto (Trace to Operation transitions):\n")
            np.savetxt(f, matrix[No:, :No], fmt='%.3f')

            f.write("\n" + "=" * 50 + "\n\n")

        # Handle both file path strings and file objects
        if isinstance(output_file, str):
            with open(output_file, 'a') as f:
                write_content(f)
        else:
            # Assume it's already a file object
            write_content(output_file)

    @staticmethod
    def calculate_transition_probabilities(trace_info: Dict, 
                                        abnormal_only: bool = False) -> Dict[str, Dict[str, float]]:
        """
        Calculate transition probabilities between operations in critical paths.
        
        Args:
            trace_info: Dictionary containing trace analysis information
            abnormal_only: Whether to consider only abnormal traces
            
        Returns:
            Dictionary of transition probabilities
        """
        transitions = defaultdict(lambda: defaultdict(int))
        outgoing_counts = defaultdict(int)

        for trace_name, analysis in trace_info.items():
            if abnormal_only and not any(t.get('trace_name') == trace_name 
                                       for t in analysis.get('abnormal_traces', [])):
                continue

            critical_path = analysis['critical_path']
            for i in range(len(critical_path) - 1):
                current_op = critical_path[i]['operation_name']
                next_op = critical_path[i + 1]['operation_name']
                transitions[current_op][next_op] += 1
                outgoing_counts[current_op] += 1

        probabilities = {}
        for source_op in transitions:
            probabilities[source_op] = {}
            for target_op in transitions[source_op]:
                probabilities[source_op][target_op] = 1.0 / outgoing_counts[source_op]

        return probabilities