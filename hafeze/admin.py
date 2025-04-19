import datetime
from django.contrib import admin, messages
from .models import ResultCheck, ClusterRef, IpCluster, Tag, IpDistance
from utils.utils import dicttoIpMeta

def show_ip(modeladmin,request,queryset):
    try:
        if len(queryset) > 1 :
            raise ValueError("select only one ip")
        for ipclus in queryset:
            note = ipclus.note.replace("tzinfo=<UTC>", "")
            ipMeta = dicttoIpMeta([eval(note)])[0]
            ipMeta.showip()
    except Exception as e:
        messages.error(request, e)

show_ip.short_description = "show ip"

def show_ip_cluster(modeladmin,request,queryset):
    try:
        if len(queryset) > 1 :
            raise ValueError("select only one ip")
        
        ipclus= IpCluster.objects.filter(cluster=queryset[0]).order_by('?').first()
        show_ip(modeladmin, request, queryset=[ipclus])
    except Exception as e:
        messages.error(request, e)

show_ip_cluster.short_description = "show ip"

class ResultCheckAdmin(admin.ModelAdmin):
    fields = ('ip','payload','source','insert_time','payload_check_result', 'signature_check_result','ml_check_result', 'note')
    # list of fields to display in django admin
    list_display = ['ip','payload','source','created_at','updated_at','payload_check_result', 'signature_check_result','ml_check_result']
    # if you want django admin to show the search bar, just add this line
    search_fields = ['ip__contains']
    # to define model data list ordering
    ordering = ('-updated_at',)
    list_filter = ('source','payload_check_result','signature_check_result','ml_check_result', 'payload')

class ClusterRefAdmin(admin.ModelAdmin):
    fields = ('cluster_label','tag','detection_source','note')
    list_display = ['id', 'created_at','updated_at','tag','cluster_label']
    list_editable = ['tag']
    search_fields = ['cluster_label__contains','id']
    ordering = ('-updated_at',)
    list_filter = ('tag','detection_source')
    readonly_fields = ['created_at']
    actions = [show_ip_cluster]


class ClusterListFilter(admin.SimpleListFilter):
    title = 'Cluster'
    parameter_name = 'cluster'

    def lookups(self, request, model_admin):
        # Customize lookups if needed
        return IpCluster.objects.values_list('cluster', 'cluster').distinct().order_by('cluster__id')

    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(cluster=self.value())

class IpClusterAdmin(admin.ModelAdmin):
    fields = ('ip','asn','traffic','cluster','update_counter','note')
    list_display = ['ip', 'created_at','updated_at','update_counter','cluster']
    search_fields = ['ip__contains']
    ordering = ('-updated_at',)
    list_filter = (ClusterListFilter,)
    readonly_fields = ['created_at']
    actions = [show_ip]



class TagAdmin(admin.ModelAdmin):
    fields = ('name',)
    list_display = ['name']
    search_fields = ['name']
    ordering = ('name',)

class IpDistanceAdmin(admin.ModelAdmin):
    fields = ('ip1','ip2','distance','created_at')
    list_display = ['created_at','ip1','ip2','distance']
    ordering = ('-created_at',)
    readonly_fields = ['created_at']


admin.site.register(ResultCheck, ResultCheckAdmin)
admin.site.register(ClusterRef, ClusterRefAdmin)
admin.site.register(IpCluster, IpClusterAdmin)
admin.site.register(Tag, TagAdmin)
admin.site.register(IpDistance, IpDistanceAdmin)
