#!/usr/bin/env python3

import json
import time
import uuid
import logging
import argparse

import invocations


if __name__ == '__main__':

    # Logging setup
    logging.basicConfig(filename='scan.log',
                        filemode='a',
                        level=logging.INFO,
                        format='%(asctime)s %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
    logger = logging.getLogger(__name__)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter('%(asctime)s %(message)s', "%H:%M:%S"))
    logger.addHandler(console)

    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--num_invocations",
                        help="Number of lambdas to invoke, default is 5",
                        default=5)
    parser.add_argument("-p", "--per_lambda",
                        help="Number of records to process per lambda, default is 10",
                        default=10)
    parser.add_argument("-b", "--bcrypt_hash",
                        help="bcrypt hash in standard $2$b format, else the bcrypt.hash file is read")

    args = parser.parse_args()

    num_invocations = int(args.num_invocations)
    per_lambda = int(args.per_lambda)
    total_hashes = num_invocations*per_lambda

    if args.bcrypt_hash:
        hash = args.bcrypt_hash
    else:
        with open('bcrypt.hash', 'r') as f:
            hash = f.read().strip()

    # Get Configuration
    config = invocations.get_config()
    queue_name = config['custom']['queueName']

    # Create Payloads
    payloads = []
    for x in range(int(num_invocations)):
        payloads.append({'start_pos': x * per_lambda,
                         'end_pos': (x + 1) * per_lambda,
                         'hash': hash})

    # Package Payloads into SQS Messages
    sqs_messages = [{'MessageBody': json.dumps(payload),
                     'Id': uuid.uuid4().__str__()} for payload in payloads]

    _start = time.time()
    invocations.put_sqs(sqs_messages, queue_name)

    _end = time.time()
    print("Time Taken to process {:,} hashes is {}s".format(total_hashes,
                                                          time.time() - _start))

    print("Checking Bucket for any results")
    if invocations.download_bucket():
        print("Found result, check result folder for more info")
        invocations.clear_bucket()
    else:
        print("No Matches found")

