import base64
import hashlib
import json
import logging
from typing import Optional

import boto3
from botocore.exceptions import ClientError


def encode_endpoint(from_connection: str, to_connection: str) -> str:
    if from_connection.endswith('=') and to_connection.endswith('='):
        try:
            from_bytes = from_connection.rstrip('=').encode()
            to_bytes = to_connection.rstrip('=').encode()
            h = hashlib.sha256()
            h.update(from_bytes)
            hd = h.digest()
            endpoint_id = bytearray(to_bytes)
            for i in range(len(endpoint_id)):
                ii = i % len(hd)
                endpoint_id[i] ^= hd[ii]
            return base64.b64encode(endpoint_id).decode().rstrip('=') + '?'
        except Exception as e:
            logging.error('Cannot encode connection: %s', e)

    return to_connection


def decode_endpoint(endpoint: str, from_connection: str) -> str:
    if endpoint.endswith('?'):
        from_bytes = from_connection.rstrip('=').encode()
        h = hashlib.sha256()
        h.update(from_bytes)
        hd = h.digest()
        endpoint_bytes = base64.b64decode(endpoint[:-1] + '==')
        endpoint_id = bytearray(endpoint_bytes)
        for i in range(len(endpoint_id)):
            ii = i % len(hd)
            endpoint_id[i] ^= hd[ii]
        return endpoint_id.decode() + '='

    return endpoint


def handler(event, context):
    request_context = event['requestContext']
    route_key = request_context['routeKey']
    connection_id = request_context['connectionId']
    domain = request_context['domainName']
    stage = request_context['stage']
    endpoint_url = f'https://{domain}/{stage}'
    api = boto3.client(service_name='apigatewaymanagementapi', endpoint_url=endpoint_url)

    if route_key == '$connect':
        if 'authorizer' in request_context:
            auth_context = request_context['authorizer']
            to_delete = auth_context.get('to_delete')
            if to_delete:
                try:
                    api.delete_connection(ConnectionId=to_delete)
                except ClientError as ce:
                    error_code = ce.response.get('Code', 'Unknown')
                    if error_code != 'GoneException':
                        logging.warning('Close connection %s error: %s', to_delete, ce)

            connection1 = auth_context.get('connection1')    # type: Optional[str]
            connection2 = auth_context.get('connection2')    # type: Optional[str]
            if connection1 and connection2:
                other_connection = connection2 if connection1 == connection_id else connection1
                try:
                    _ = api.get_connection(ConnectionId=other_connection)
                    data = {
                        'PairConnection': encode_endpoint(other_connection, connection_id),
                        'Command': 'HELO'
                    }
                    api.post_to_connection(Data=json.dumps(data), ConnectionId=other_connection)
                except ClientError as ce:
                    logging.warning(f'The pair connection {other_connection} error: {ce}')
        return {'statusCode': 200}

    elif route_key == '$disconnect':
        return {'statusCode': 200}

    elif route_key == '$default':
        body = event.get('body')
        if body:
            input_data = json.loads(body)
            target = input_data.get('PairConnection')
            if target:
                target_connection = decode_endpoint(target, connection_id)
                input_data['PairConnection'] = encode_endpoint(target_connection, connection_id)
                try:
                    input_body = json.dumps(input_data)
                    api.post_to_connection(Data=input_body, ConnectionId=target_connection)
                    output_data = {
                        'PairConnection': target,
                        'Command': 'ACK'
                    }
                    output_body = json.dumps(output_data)
                    api.post_to_connection(Data=output_body, ConnectionId=connection_id)

                    return {'statusCode': 200}

                except ClientError as ce:
                    logging.error('Post to pair connection %s error: %s', target_connection, ce)
                    output_data = {
                        'PairConnection': target,
                        'Command': 'NAK',
                        'Error': str(ce)
                    }
                    output_body = json.dumps(output_data)
                    api.post_to_connection(Data=output_body, ConnectionId=connection_id)
                    return {'statusCode': 200}
            else:    # TODO control message
                pass

        return {'statusCode': 200}
    else:
        return {'statusCode': 404}
