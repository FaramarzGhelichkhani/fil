from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema


def swagger_auto_schema_domain_ips(view_func):
    return swagger_auto_schema(
    method='GET',
    tags=['get domain data'],
    operation_id='get_domain_ips',
    operation_description='ای پی های ریزالو شده به یک هاست دی  ان اس در یک روز اخیر',
    operation_summary='Get the resolved ips for a dns host',
    responses={
        200: openapi.Response(
            description='Successful response',
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'domain': openapi.Schema(type=openapi.TYPE_STRING),
                    'server_ips': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(type=openapi.TYPE_STRING)
                    ),
                    'resolved_ips_raw': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(type=openapi.TYPE_STRING)
                    ),
                    'suggested_ips': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(type=openapi.TYPE_STRING)
                    ),
                }
            )
        ),
        400: 'Invalid request'
    }
)(view_func)



def swagger_auto_schema_domain_hit(view_func):
    
    return swagger_auto_schema(
    method='GET',
    tags=['get domain data'],
    operation_id='get_domain_hit',
    operation_summary='Get the hit count for a domain',
    operation_description="تعداد هیت های  دامنه مذکور که در ایندکس دی ان اس وجود داشته",
    manual_parameters=[
        openapi.Parameter(
            name='domain',
            in_=openapi.IN_PATH,
            type=openapi.TYPE_STRING,
            description='The domain for which to get the hit count',
            required=True,
        )
    ],
    responses={
        200: openapi.Response(
            description='Successful response',
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'domain': openapi.Schema(type=openapi.TYPE_STRING),
                    'hit': openapi.Schema(type=openapi.TYPE_INTEGER),
                }
            )
        ),
        400: 'Invalid request'
    }
    )(view_func)



def swagger_auto_schema_UI_GET(view_func):
    return swagger_auto_schema(
        operation_id='get_ui',
        tags=['signature'],
        operation_summary='Get the output data  for a signature or script',
        operation_description= ":دریافت ای پی های خروجی ویا تشخیصی یک اسکریپت. فرمت خروجی \n"+'\n'+'json\n',
        responses={200: 'Successful response'}
    )(view_func)



def swagger_auto_schema_UI(view_func):
    return  swagger_auto_schema(
        operation_id='post_ui',
        tags=['signature'], 
        operation_summary='Submit the UI form for processing script.',
        operation_description="جهت ران کردن اسکریپت بر روی ای پی متا های آخرین روز موجود در فیل. هم چنین امکان گرفتن ا ی پی ورودی نیز فراهم است. داده های خروجی را نیر می توان دانلود کرد"
        ,request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'download': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                'input_ips': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_STRING)),
                'unlabeled_limit': openapi.Schema(type=openapi.TYPE_INTEGER),
                'signature': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['download', 'input_ips', 'unlabeled_limit', 'signature']
        ),
        responses={200: 'Successful response'}
    )(view_func)