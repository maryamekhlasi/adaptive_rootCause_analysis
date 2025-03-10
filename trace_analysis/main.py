import os
from analyzers.trace_analyzer import TraceAnalyzer

def main():
    # Your existing main function code here
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