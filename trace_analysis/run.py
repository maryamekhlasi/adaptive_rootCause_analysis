import os
from trace_analysis.analyzers.trace_analyzer import TraceAnalyzer

def main():
    # Create analyzer instance
    analyzer = TraceAnalyzer()
    
    # Get current working directory
    current_dir = os.getcwd()
    
    # Create output directory if it doesn't exist
    output_dir = os.path.join(current_dir, "analysis_output")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Define input and output paths
    #input_dir = "/path/to/your/traces"  # Update this path
    input_dir = r"/home/maryam/Poly/Dorsal/traces/dataset/article/article-3"
    output_file = os.path.join(output_dir, "trace_analysis_results.txt")
    
    # Run analysis
    print("Starting trace analysis...")
    results = analyzer.analyze_all_traces(input_dir)
    
    # Write results
    analyzer.write_analysis_results(output_file)
    print(f"Analysis complete. Results written to {output_file}")

if __name__ == "__main__":
    main()