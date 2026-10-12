"""Compatibility entry point for the packaged raw-name diagnostic."""
from analyzer.backends.raw_names import main, select_raw_name, dump_resources, subprocess

if __name__ == '__main__':
    main()
