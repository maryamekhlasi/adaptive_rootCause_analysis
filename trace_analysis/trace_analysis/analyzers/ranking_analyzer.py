import numpy as np

class RankingAnalyzer:
    @staticmethod
    def calculate_pagerank(matrix, damping_factor=0.85, epsilon=1e-8, max_iterations=100, preference_vector=None):
        """Calculate PageRank scores for the given matrix"""
        n = matrix.shape[0]
        
        if preference_vector is None:
            preference_vector = np.ones(n) / n
            
        v = np.ones(n) / n
        
        for _ in range(max_iterations):
            v_next = damping_factor * np.dot(matrix, v) + (1 - damping_factor) * preference_vector
            if np.sum(np.abs(v_next - v)) < epsilon:
                return v_next
            v = v_next
            
        return v