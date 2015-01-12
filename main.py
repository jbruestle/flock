#!/usr/bin/env python
#pylint: disable=missing-docstring

import logging
import argparse

import node

def main():
    # Parse some params
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", help="Storage directory")
    args = parser.parse_args()

    # Logging system GO
    logging.basicConfig(level=logging.INFO)

    the_node = node.Node(args.dir, {})
    the_node.run()

main()


