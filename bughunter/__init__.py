"""Agentic Bug Hunter — packaged distribution.

The modules inside this package (agent, brain, engine, serve, tools.*) were
written to run from a directory on sys.path. The console-script launchers in
__main__ put this package directory on sys.path before dispatching, so those
flat imports keep resolving after a pip install.
"""
__version__ = "6.0.1"
