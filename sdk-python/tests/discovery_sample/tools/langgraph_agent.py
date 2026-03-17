"""LangGraph tool calls — should be detected as execution."""
from langgraph.graph import StateGraph

def build_graph():
    graph = StateGraph(dict)
    graph.add_node("search", lambda s: s)
    graph.add_node("analyze", lambda s: s)
    graph.add_edge("search", "analyze")
    return graph
