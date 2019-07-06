#!/usr/bin/env python3
# CI Test script: generate all queries with eql backend.
# Copyright 2019 Zack Payton @zackpayton

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.



from eql import parse_query, ParseError
import argparse, sys

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='check an eql query for valid syntax against the eql parser')
    parser.add_argument('--query', '-q', help='the eql query to check for valid syntax')
    args = parser.parse_args()

    if not args.query:
        print("Must specify the --query or -q parameter")
        sys.exit(-1)

    eql_query = args.query

    try:
        _ = parse_query(eql_query)
    except ParseError as e:
        print("eql_error: {0}".format(e.message))
        sys.exit(-1)
    sys.exit(0)