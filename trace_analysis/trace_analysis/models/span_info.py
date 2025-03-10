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