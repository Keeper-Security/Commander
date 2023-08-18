# import datetime
# import logging
# from typing import Optional
#
# import boto3
# from botocore.exceptions import ClientError
#
# dynamodb = boto3.resource('dynamodb')
#
#
# def handler(event, context):
#     request_context = event['requestContext']
#     connection_id = request_context['connectionId']
#
#     authorization: Optional[str] = event['headers'].get('Authorization')
#     try:
#         if not authorization:
#             raise Exception('Authorization: empty')
#
#         scheme, sep, params = authorization.partition(' ')
#         if scheme.upper() != 'DYNAMO-TUNNEL':
#             raise Exception('Authorization: invalid scheme')
#
#         parameters = {}
#         for param in params.split(','):
#             param = param.strip()
#             if not param:
#                 continue
#             key, sep, value = param.partition('=')
#             key = key.strip()
#             if key:
#                 parameters[key.lower()] = value.strip()
#         endpoint_id = parameters.get('request_id')
#
#         if not endpoint_id:
#             raise Exception('Authorization: "endpoint_id" parameter is missing')
#
#         tunnel_table = dynamodb.Table('tunnel')
#         key = {'request_id': endpoint_id}
#         rs = tunnel_table.get_item(Key=key)
#         item = rs['Item']
#
#         connection_no = 0
#
#         unique_user_id = parameters.get('user_id') or ''
#         if unique_user_id:
#             user1 = item.get('user1') or ''
#             user2 = item.get('user2') or ''
#             if user1 == unique_user_id:
#                 connection_no = 1
#             elif user2 == unique_user_id:
#                 connection_no = 2
#
#         connection1 = item.get('connection1') or ''
#         connection2 = item.get('connection2') or ''
#         if connection_no == 0:
#             if connection_id == connection1:
#                 connection_no = 1
#             elif connection_id == connection2:
#                 connection_no = 2
#
#         if connection_no == 0:
#             if connection1 and connection1 == connection_no:
#                 connection_no = 1
#             elif connection2 and connection2 == connection_no:
#                 connection_no = 2
#             elif not connection1:
#                 connection_no = 1
#             elif not connection2:
#                 connection_no = 2
#
#         if connection_no == 0:
#             raise Exception('Endpoint is full')
#
#         context = {}
#         if connection_no == 1:
#             if connection1 and connection1 != connection_id:
#                 context['to_delete'] = connection1
#             item['connection1'] = connection_id
#             if unique_user_id:
#                 item['user1'] = unique_user_id
#         elif connection_no == 2:
#             if connection2 and connection2 != connection_id:
#                 context['to_delete'] = connection2
#             item['connection2'] = connection_id
#             if unique_user_id:
#                 item['user2'] = unique_user_id
#
#         context['connection1'] = item.get('connection1')
#         context['connection2'] = item.get('connection2')
#
#         dt = datetime.datetime.now() + datetime.timedelta(hours=4)
#         item['ExpireAt'] = int(round(dt.timestamp()))
#         tunnel_table.put_item(Item=item, ReturnValues='NONE')
#
#         return {
#             'principalId': unique_user_id or 'user',
#             'policyDocument': {
#                 'Version': '2012-10-17',
#                 'Statement': [
#                     {
#                         'Action': 'execute-api:Invoke',
#                         'Effect': 'Allow',
#                         'Resource': event['methodArn']
#                     }
#                 ]
#             },
#             'context': context
#         }
#     except ClientError as ce:
#         logging.error('DynamoDB: Get endpoint error: %s', ce)
#     except Exception as e:
#         logging.error('Lambda: Get endpoint error: %s', e)
#
#     return {
#         'principalId': 'user',
#         'policyDocument': {
#             'Version': '2012-10-17',
#             'Statement': [{
#                 'Action': 'execute-api:Invoke',
#                 'Effect': 'Deny',
#                 'Resource': event['methodArn']
#             }]
#         }
#     }
