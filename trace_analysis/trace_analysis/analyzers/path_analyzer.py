from collections import defaultdict
import numpy as np

class PathAnalyzer:
    @staticmethod
    def merge_intervals(intervals):
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

    @staticmethod
    def calculate_statistics(critical_path):
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