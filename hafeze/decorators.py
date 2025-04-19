from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema


def swagger_auto_schema_ip_traffic(view_func):
    schema = {
        'methods': ['POST'],
        'tags': ['get ip data'],
        'operation_summary':"Get IP's traffic",
        'operation_description': "    تابع جهت دریافت ترافیک یک لیست از ای پی ها. هم چنین اطلاعات مربوط به اس و زمان هر ای پی نیز داده می شود",
        'request_body': openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'ips': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_STRING),
                    example = ['8.8.8.8','4.4.4.4']
                )
            },
            required=['ips']
        ),
        'responses': {
            200: openapi.Response(
                description='Successful response',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'data': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    'ip': openapi.Schema(type=openapi.TYPE_STRING),
                                    'traffic': openapi.Schema(type=openapi.TYPE_INTEGER),
                                    'time': openapi.Schema(type=openapi.TYPE_STRING),
                                    'asn': openapi.Schema(type=openapi.TYPE_INTEGER),
                                }
                            )
                        ),
                        'total_traffic': openapi.Schema(type=openapi.TYPE_INTEGER),
                    }
                )
            ),
            400: 'Invalid request'
        }
    }

    return swagger_auto_schema(**schema)(view_func)



def swagger_auto_schema_ipmeta_api(view_func):
    schema = {
    'methods': ['POST'],
    'tags': ['get ip data'],
    'operation_summary':'Get IP Meta Data',
    'operation_description': 'دریافت آی پی متا برای بازه زمانی مشخص. خروجی به صورت جیسون خواهد بود' ,  
    
    'request_body':openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'days_ago': openapi.Schema(
                type=openapi.TYPE_INTEGER,
                description='Number of days ago from which to retrieve IP meta data.'
            ),
            'ip_list': openapi.Schema(
                type=openapi.TYPE_ARRAY,
                items=openapi.Schema(type=openapi.TYPE_STRING),
                description='List of IP addresses.',
                example = ['8.8.8.8','4.4.4.4']
            ),
        },
        required=['days_ago', 'ip_list']
    ),
    'responses':{
        200: openapi.Response(
            description='Successful response',
             content={
                'application/octet-stream': {
                    'schema': {
                        'type': 'json',
                        'format': 'json'
                    }
                }
            }
        ),
        400: 'Invalid request'
    }
    }

    return swagger_auto_schema(**schema)(view_func)



def swagger_auto_schema_ipmeta_ui(view_func):
    return swagger_auto_schema(
    method='POST',
    tags= ['get ip data'],
    operation_summary='Get IP Meta UI',
    operation_description='\nدریافت  آی پی متا های یک لیست به صورت فرمت \n' + '\njson\n' + '\nاین داده ها بر اساس داده هایی که قبلا موجود هستند بدست می ایند می توان با گزینه\n' + '\nproduce\n' +'\nداده جدید بدست آورد\n' + '\n فرم و رابط کاربری نیز موجود است\n',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'ips': openapi.Schema(
                type=openapi.TYPE_STRING,
                description='Comma-separated list of IP addresses.',
                example='8.8.8.8, 10.0.0.1'
            ),
            'days_ago': openapi.Schema(
                type=openapi.TYPE_INTEGER,
                description='Number of days ago from which to retrieve IP meta data.',
                example = '0 means today 1 means yesterday'
            ),
            'produce': openapi.Schema(
                type=openapi.TYPE_BOOLEAN,
                description='Flag indicating whether to produce IP meta data.'
            ),
            'download': openapi.Schema(
                type=openapi.TYPE_BOOLEAN,
                description='Flag indicating whether to download the IP meta data as a JSON response.'
            ),
        },
        required=['ips', 'produce', 'download']
    ),
    responses={
        200: openapi.Response(
            description='Successful response',
            content={'application/json': {}}
        ),
        400: openapi.Response(
            description='Bad Request',
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description='Error message indicating the cause of the bad request.'
                    )
                }
            )
        )
    },
    operation_id='get_ipmeta_ui',
    operation_parameters=[
        openapi.Parameter(
            name='x-proxy',
            in_=openapi.IN_HEADER,
            type=openapi.TYPE_STRING,
            description='The proxy server used for the API request.'
        )
    ]
    )(view_func)
