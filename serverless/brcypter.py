import os
import json
import logging
import uuid

import bcrypt
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def upload_to_s3(hash, password):
    """
    Uploads matching hash and password to s3 bucket specified in os.environ
    Args:
        hash    (string): The hash in text form
        password(string): The password that matched the hash

    Returns:
        bool: True if file was uploaded, False otherwise
    """

    s3 = boto3.resource('s3')
    try:
        bucket = s3.Bucket(os.environ['bucket_name'])
        file_name = f"/tmp/{uuid.uuid4().__str__()}.txt"

        with open(file_name, 'w') as f:
            f.write(f"{hash},{password}\n")

        bucket.upload_file(file_name, file_name.replace('/tmp/', ''))
    except KeyError:
        logger.info("No bucket specified")

    return True


def check_hash(hash, start_pos, end_pos):
    """
    Checks the hash against a sub-set of passwords in the password file.

    Args:
        hash      (string): The hash in text form (needs to be encoded to binary)
        start_pos (int): The starting position for the subset
        end_pos   (int): The ending position of the subset
    Returns:
        bool: Returns False if no password found, True if found

    """

    passwords_file = '/opt/1000000.passwords.txt'

    hash_binary = hash.encode('utf-8')

    with open(passwords_file, 'r') as f:
        passwords = f.readlines()
        logger.info(f'Checking hashes from {start_pos} to {end_pos}')
        for password in passwords[start_pos:end_pos]:
            if bcrypt.checkpw(password.strip().encode('utf-8'), hash_binary):
                # We don't log the passwords or hash for security reasons. Passwords and hashes only stored in S3.
                logger.info(f"SUCCESS: Found a Password for -- check {os.environ['bucket_name']}")
                upload_to_s3(hash, password.strip())
                return password
        else:
            return False


def main(event, context):

    # Get message off the Queue
    try:
        message = json.loads(event['Records'][0]['body'])
    except (json.JSONDecodeError, KeyError):
        logger.error("JSON Decoder error for event: {}".format(event))
        return {'statusCode': 500}

    # Parse the message and check for matches
    try:
        hash = message['hash']
        start_pos = message['start_pos']
        end_pos = message['end_pos']
        logger.info("Checking Hashes...")
        logger.info(f"Hash for {hash}")
        success = check_hash(hash, start_pos, end_pos)
    except KeyError:
        logger.error("One or more expected variables missing in Queue Message")
        return {'statusCode': 500}

    # Return
    if success:
        return {'statusCode': 200}
    else:
        return {'statusCode': 404}


if __name__ == '__main__':

    os.environ['bucket_name'] = 'bcrypter.123456'
    password = check_hash("$2b$12$1WWoYzclPZq6cDCLgGRE2urogi3M1lRb12402WmGoFHwGV638UIpO", 20, 30)
    if password:
        print(password)
    else:
        print("Unable to find password")