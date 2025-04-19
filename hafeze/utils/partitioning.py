import logging
import pickle
import pandas as pd 
import numpy as np
import joblib
import datetime
from aaj.utils.worker import Worker
from fil.settings import REDIS_IP_HOURLY_DB, PARTITIONING_NUMBER_OF_MIN_SAMPLE, PARTITIONING_INTERVAL_DAYS, PARTITIONING_IP_UPDATE_COUNTER, PARTITIONING_EPSILON , PARTITIONING_PROCESSORS_NUMBER, PARTITIONING_SIMILARITY_MODEL, PARTITIONING_MAXIMUM_IP_INSTANCES
from hafeze.models import ClusterRef, IpCluster, IpDistance
from utils import mlflow_handler
from utils.file_handler import get_keys_from_redis, load_objects_from_redis
from joblib import Parallel, delayed
from aaj.utils.similarity import Similarity 
from sklearn.cluster import DBSCAN
from django.utils import timezone
from django.db.models import Sum
from aaj.utils.worker import chunking_data
from multiprocessing import Pool
from utils.ipmeta.main import produce_ipmeta_clickhouse
from utils.utils import todict, dicttoIpMeta
from itertools import combinations
from aaj.utils.distance import Utils


logger = logging.getLogger("ip_classification.main")

class Partition:

    def __init__(self, min_sample=PARTITIONING_NUMBER_OF_MIN_SAMPLE, interval_day=PARTITIONING_INTERVAL_DAYS, update_counter=PARTITIONING_IP_UPDATE_COUNTER, eps=PARTITIONING_EPSILON, 
    percent=50, processor_number=PARTITIONING_PROCESSORS_NUMBER, mlflow_version=PARTITIONING_SIMILARITY_MODEL, detection_source='other', redis_host=None, redis_db=REDIS_IP_HOURLY_DB):
        mlflow = mlflow_handler.MlflowHandeler("RandomForestSimilarity_Fil")
        self.model = mlflow.load_model(version=mlflow_version)
        #   self.model = joblib.load('/var/fil/data/models/RandomForestSimilarity_Fil.joblib')
        self.percent = percent
        self.eps = eps
        self.min_sample = min_sample
        self.interval_day = interval_day
        self.update_counter = update_counter
        self.processor_number = processor_number
        self.df=pd.DataFrame()
        self.new_ipcluster_instances= []
        self.new_ip_distance_instances= []
        self.update_ipcluster_instances= []
        self.update_clusterref_instances= []
        #self.cluster_id_null_domain = ClusterRef.objects.get(cluster_label='null-domain').id
        self.cluster_id_negative = ClusterRef.objects.get(cluster_label='-1', detection_source=detection_source).id
        self.dict_ipmeta_other_clusters = {}
        self.dict_ipmeta_1_clusters = {}        
        self.end_date = timezone.now()
        self.start_date = self.end_date - timezone.timedelta(days=self.interval_day)
        self.redis_host=redis_host
        self.detection_source = detection_source
        self.redis_db= redis_db

    def initiate(self):
        logger.info(f"making cluster start for {self.percent} : of {self.detection_source}'s traffic. ___initiate___")
        
        keys = get_keys_from_redis(self.redis_db, redis_host=self.redis_host)
        ipmetas = load_objects_from_redis(keys,self.redis_db,redis_host=self.redis_host)

        m = Multiprocessing()
        func_name = 'initiate_'  + self.detection_source
        res = m.base_calalculate_parallel(model=None, data=ipmetas, processor_number=self.processor_number, func_name=func_name)

        other_ip = []
        for ipmetas in res:
            other_ip.extend(ipmetas)

        # region 50 percent trafficly.
        sorted_other = sorted(other_ip, key=lambda x: x.total_traffic, reverse=True)[:PARTITIONING_MAXIMUM_IP_INSTANCES]
        other_ip.clear()

        df = pd.DataFrame([[ip, ip.total_traffic, self.detection_source] for ip in sorted_other]
                  ,columns=["ip_obj", "total_traffic", "detection_source"])
        
        sorted_other.clear()
        df['cum_perc'] = 100* df['total_traffic'].cumsum()/df['total_traffic'].sum()

        sample_df =  df.loc[df.cum_perc <= self.percent]
        df = pd.DataFrame()

        # endregion
        sample_df["cluster"] = None
        sample_df["label"] = None
        sample_df["cluster_id"] = None
        logger.info(f"number of ip instances: {sample_df.shape[0]}. ___initiate___")
        logger.info(f"finish initiate ___initiate___", {"command": "initiate"})    

        return sample_df

    def base_partitioning_algorithm(self):
        self.df = self.initiate()

        self.dict_ipmeta_other_clusters = self.get_center('other')
        self.dict_ipmeta_1_clusters = self.get_center(cluster_group='-1')
        # logger.info(f"finish fetching get_center", {"command": "get_center"})

        self.searching_duplicate_ip()

        ipmeta_inputs = self.df['ip_obj'].tolist()        
        if len(ipmeta_inputs) > 0:
            _ = self.find_similar_ip_with_other_cluster(cluster_group='-1', ipmeta_inputs=ipmeta_inputs)
             
        self.df = self.extend_cluster_1_DB_to_input_df()
        self.df['cluster'] = self.clustering_ip(using_db=True)
        labels = self.cluster_labeling()
        self.df['label'] = self.df.apply(lambda x: labels[x['cluster']], axis=1)
        self.append_instance(self.create_cluster(self.df)) # all cluster will add even  -1
 
        ips_db = [ip for ip in self.dict_ipmeta_1_clusters.keys()]
        total_assigned = [ipmeta.ip for ipmeta in self.df['ip_obj'][self.df['cluster'] != -1]]
        drop_ip_cluster_1 = []
        for ip in ips_db:
            if ip in total_assigned:
                drop_ip_cluster_1.append(ip)        

        self.remove_negative_rows(ips=drop_ip_cluster_1)
        self.save_ip()
   
    def base_clustering_algorithm(self):
        """
        (1) cluster new ips with theme
        (2) labeling new cluster for access to 'null domain and drop theme' in next step)
        (3) adding null domain to null domain cluster database and drop from df
        (4) adding leader new cluster to centroid cluster)
        (5) adding new cluster to database
        (6) check to adding new cluster to datbase for (new -1 cluster) and (past -1 cluster)
        (7) update all of (cluster -1) (past and new)     
        (8) save into ipcluster in the end
        """        

        self.df = self.initiate()

        self.dict_ipmeta_other_clusters = self.get_center('other')
        self.dict_ipmeta_1_clusters = self.get_center(cluster_group='-1')
        logger.info(f"finish fetching get_center __base_clustering_algorithm___", {"command": "base_clustering_algorithm"})
 
        # self.drop_null_domain()

        self.df['cluster'] = self.clustering_ip()

        labels = self.cluster_labeling()
        self.df['label'] = self.df.apply(lambda x: labels[x['cluster']], axis=1)
        logger.info(f"finish cluster labeling ___base_clustering_algorithm___", {"command": "cluster_labeling"})        

        ipmeta_inputs = self.df[self.df['cluster'] != -1].groupby('cluster').first()['ip_obj'].tolist()
        center_new_ipmeta_clusters = self.find_similar_ip_with_other_cluster(cluster_group='other', ipmeta_inputs=ipmeta_inputs)
        self.adding_new_cluster_database(center_new_ipmeta_clusters, cluster_group='other')

        ipmeta_inputs = self.df[self.df['cluster'] == -1]['ip_obj'].tolist()
        remain_1_ipmetas = self.find_similar_ip_with_other_cluster(cluster_group='-1', ipmeta_inputs=ipmeta_inputs)

        remain_1_ipmetas, remove_ipmeta_1_clusters = self.find_similar_ip_with_cluster_1(remain_1_ipmetas)

        self.adding_new_cluster_database(remain_1_ipmetas, cluster_group='-1')       
        
        self.remove_negative_rows(ips=remove_ipmeta_1_clusters)

        self.save_ip()
   
    def cal_domain_dist(self, i, ipmetas):
        
        num_samples = len(ipmetas)
        result=[]

        for j in range(i+1, num_samples):
            s = Similarity.ip(ipmetas[i],  ipmetas[j],dist_type='domain')
            diff= 1- np.array(list(s.values())) 
            euclidean_dist= np.sqrt(np.sum(diff**2)) 
            result.append(euclidean_dist)

        return result        

    def cal_domain_distance_matrix(self):
        num_workers=12
        other_ipmeta_sample = self.df["ipmeta"].tolist()
        upper_triangle_distances = Parallel(n_jobs=num_workers)(
            delayed(self.cal_domain_dist)(i, other_ipmeta_sample) for i in range(len(other_ipmeta_sample))
        )
        distance_matrix = np.zeros((len(other_ipmeta_sample), len(other_ipmeta_sample)))
        for i, distances_row in enumerate(upper_triangle_distances):
            distance_matrix[i, i+1:] = distances_row

        distance_matrix += distance_matrix.T   

        return distance_matrix

    def cal_matrix(self, df):
        num_instances = df.shape[0]
        distance_matrix = np.ones((num_instances, num_instances))
        ipmeta_list  = df['ip_obj'].tolist()
        data_list = []
        
        for i in range(len(ipmeta_list)):
            for j in range(i,len(ipmeta_list)):
                data_list.append([ipmeta_list[i], ipmeta_list[j], i, j])

        m = Multiprocessing()
        res = m.base_calalculate_parallel(model=self.model,data=data_list, processor_number=self.processor_number, func_name='cal_dist_parallel')

        for element in res:
            for elem in element:
                i = elem[1][0]
                j = elem[1][1]
                distance_matrix[i, j] = elem[0]
                distance_matrix[j, i] = elem[0]

        return distance_matrix

    def clustering_ip(self, using_db=False):
        logger.info("start to clustering. ___clustering_ip___")
        if not using_db: 
            ip_distance_matrix = self.cal_matrix(self.df)
        else:
            ip_distance_matrix = self.create_distance_matrix_with_db_pairs(ipmetas=self.df.ip_obj.to_list())
        return self.dbscan_clustering(ip_distance_matrix)

    def clustering_domain(self):
        domain_ditsance_matrix = self.cal_domain_distance_matrix()
        self.df["cluster_domain"] = self.dbscan_clustering(domain_ditsance_matrix, esp=1.16)
    
    def dbscan_clustering(self,distance_matrix):
        dbscan = DBSCAN(eps=self.eps, min_samples=self.min_sample, metric='precomputed')
        labels = dbscan.fit_predict(distance_matrix)
        logger.info(f"number of generated clusters by dbscan: {len(np.unique(labels))} ___dbscan_clustering___")
        return labels

    def ipmetas_lableing(self, ipmetas):
        res = {}
        for ip in ipmetas:
            for dom in  ip.domain_dist:
                
                res.setdefault(dom.domain,0)
                res[dom.domain]+= (1/len(ipmetas) )
                if dom.domain == 'null-domain' and len(ip.domain_dist) > 1:
                    del res[dom.domain]
        sorted_res = sorted(res.items(),key=lambda x: x[1], reverse= True)
                    
        return sorted_res[0][0] if sorted_res[0][1] > 0.66 else None

    def cluster_labeling(self):
        labels= {-1:"-1"}
        for domclus in self.df["cluster"].unique():
            if domclus != -1:
                ip_objs = self.df.query(f"cluster == {domclus}")["ip_obj"]
                ipmetas = [ ip for ip in ip_objs]
                label = self.ipmetas_lableing(ipmetas=ipmetas)
                labels[domclus] = label

        return labels 

    def drop_null_domain(self):
        df_null = self.df[self.df['ip_obj'].apply(lambda x: len(x.domain_dist) == 1 and x.domain_dist[0].domain == 'null-domain')]
        self.update_null_domain(df_null)
        logger.info(f"finish drop null_domain ___drop_null_domain___", {"command": "drop_null_domain"})

    def update_null_domain(self, df):
        #self.df['cluster_id'][self.df[self.df['label'] == 'null-domain']] = self.cluster_id_null_domain
        df['cluster_id'] = self.cluster_id_null_domain
        tmp_df = df[df['cluster_id'] == self.cluster_id_null_domain]
        logger.info(f"number of null-domain instances: {tmp_df.shape[0]} ___update_null_domain___")
        self.append_instance(tmp_df)
        self.df = self.df.drop(tmp_df.index)

    def update_df(self):
        similar_instaces_df = self.df[~self.df['cluster_id'].isnull()]
        logger.info(f"number of similar ipmeta_input(without -1) with db clusters: {similar_instaces_df.shape[0]} ___update_df___", {"command": "update_df"})
        self.append_instance(similar_instaces_df)
        self.df = self.df.drop(similar_instaces_df.index)

    def extend_cluster_1_DB_to_input_df(self):

        ipmetas_db = []
        for ipmeta_DB in self.dict_ipmeta_1_clusters.values():
            if ipmeta_DB[1].ip not in [ipmeta_df.ip for ipmeta_df in self.df['ip_obj']]:
                ipmetas_db.append(ipmeta_DB[1])

        #ipm_df = [ip.ip for ip in self.df.ip_obj]
        for i in ipmetas_db:
            self.df.loc[-1] = [i, i.total_traffic, 'other', None, None, None, None]
            self.df.index = self.df.index + 1 
        self.df.reset_index().drop(['index'], axis=1)

        logger.info(f"finish extending, and ready for clustering {len(self.df)} ___extend_cluster_1_DB_to_input_df___", {"command": "extend_cluster_1_DB_to_input_df"})
        return self.df
    
    def adding_new_cluster_database(self, ipmetas, cluster_group='-1'):
        ipmetas_dump = [ipmeta for ipmeta in ipmetas]
        if cluster_group == '-1':
            self.df['cluster'] =  self.df.apply(lambda x: 'tmp' if x['ip_obj'] in ipmetas_dump else x['cluster'], axis=1)
            tmp_df = self.df[self.df['cluster'] == 'tmp']
            tmp_df['cluster'] = len(tmp_df)*[-1]
            tmp_df['label'] = len(tmp_df)*['-1']
            tmp_df['cluster_id'] = self.cluster_id_negative
            self.append_instance(tmp_df)
            self.df = self.df.drop(self.df[self.df['cluster'] == 'tmp'].index)
            logger.info(f"number of new instance for negative cluster: {len(ipmetas_dump)} ___adding_new_cluster_database___") 
        else:
            for center_ipmeta in ipmetas_dump:
                try:
                    tmp_df = self.df[self.df['cluster'] == self.df['cluster'][self.df.apply(lambda x: x['ip_obj'].ip == center_ipmeta.ip, axis=1)].values[0]]
                    ipmeta_clusters = tmp_df['ip_obj'].tolist()
                    new_label = self.ipmetas_lableing(ipmeta_clusters)
                    tmp_df['label'] = new_label
                    self.append_instance(self.create_cluster(tmp_df))
                    self.df = self.df.drop(tmp_df.index)    
                except:
                    logger.warn(f"errors when adding new_center_cluster ___adding_new_cluster_database___", {"command": "adding_new_cluster_database"})

            logger.info(f"added {len(ipmetas_dump)} new clusters___adding_new_cluster_database___", {"command": "adding_new_cluster_database"})                 
                
    def find_similar_ip_with_cluster_1(self, ipmeta_inputs):

        m = Multiprocessing()
        res = m.base_calalculate_parallel(model=self.model, data=ipmeta_inputs, processor_number=self.processor_number, func_name='calculate_sim_1_parallel', args_dict=self.dict_ipmeta_1_clusters)
        
        aggregate_result = {}
        for ipmeta in res:
            aggregate_result.update(ipmeta)

        dict_similar_ipmeta = {}
        for ipmeta_input_1, ipmeta_cluster_1 in aggregate_result.items():
            if len(ipmeta_cluster_1) != 0:
                dict_similar_ipmeta[ipmeta_input_1] = ipmeta_cluster_1 

        # total_ipmetas = []
        # total_ipmetas.extend([ipmeta for ipmeta in ipmeta_inputs])
        # total_ipmetas.extend([ipmeta[1] for ipmeta in self.dict_ipmeta_1_clusters.values()])

        # assign_clusters = []
        # for ipmeta, similar_ipmetas in dict_similar_ipmeta.items():
        #     if len(similar_ipmetas) > self.min_sample:
        #         new_cluster = [ipmeta]
        #         new_cluster.extend(similar_ipmetas)
        #         new_cluster_dump = [ipmeta.ip for ipmeta in new_cluster]
        #         self.df['cluster'] =  self.df.apply(lambda x: 'tmp' if x['ip_obj'].ip in new_cluster_dump else x['cluster'], axis=1)
        #         tmp_df = self.df[self.df['cluster'] == 'tmp']
        #         new_label = self.ipmetas_lableing(new_cluster)
        #         tmp_df['label'] = new_label
        #         self.append_instance(self.create_cluster(tmp_df))
        #         self.df = self.df.drop(tmp_df.index)
        #         assign_clusters.append(ipmeta)

        assign_clusters = []
        past_cluster_1_ipmetas = []
        for ipmeta, similar_ipmetas in dict_similar_ipmeta.items():
            if len(similar_ipmetas) >= self.min_sample:
                past_cluster_1_ipmetas.extend(similar_ipmetas)
                new_cluster = [ipmeta]
                new_cluster.extend(similar_ipmetas)
                new_cluster_dump = [ipmeta.ip for ipmeta in new_cluster]
                self.df.apply(lambda x: 'tmp' if x['ip_obj'].ip in new_cluster_dump else x['cluster'], axis=1)
                self.df['cluster'] =  self.df.apply(lambda x: 'tmp' if x['ip_obj'].ip in new_cluster_dump else x['cluster'], axis=1)
                tmp_df = self.df[self.df['cluster'] == 'tmp']
                delete_index = tmp_df.index
                assign_clusters.extend(tmp_df['ip_obj'].tolist())
                
                for i in new_cluster:
                    tmp_df.loc[-1] = [i, i.total_traffic, 'other', None, 'tmp', '-1', None]
                    tmp_df.index = tmp_df.index + 1        
                
                new_label = self.ipmetas_lableing(new_cluster)
                
                tmp_df['label'] = new_label
                self.append_instance(self.create_cluster(tmp_df))
                self.df = self.df.drop(delete_index)

        remain_ipmetas = []        
        for ipmeta in ipmeta_inputs:
            if ipmeta.ip not in [ipmeta_cluster.ip for ipmeta_cluster in assign_clusters]:
                remain_ipmetas.append(ipmeta)        
        
        return remain_ipmetas, past_cluster_1_ipmetas

    def find_similar_ip_with_other_cluster(self, cluster_group, ipmeta_inputs):
        if len(self.dict_ipmeta_other_clusters) == 0:
            return ipmeta_inputs
        
        m = Multiprocessing()
        res = m.base_calalculate_parallel(model=self.model, data=ipmeta_inputs, processor_number=self.processor_number, func_name='calculate_sim_others_parallel', args_dict=self.dict_ipmeta_other_clusters)

        aggregate_result = {}
        for ipmeta in res:
            aggregate_result.update(ipmeta)

        dict_similar_ipmeta = {}
        for ipmeta_input, ipmeta_center_cluster in aggregate_result.items():
            if len(ipmeta_center_cluster) != 0:
                dict_similar_ipmeta[ipmeta_input] = ipmeta_center_cluster    

        if cluster_group == '-1':
            assign_new_ipmeta_cluster_1 = []
            for ipmeta, similar_ipmetas in dict_similar_ipmeta.items():
                try:
                    best_similar_cluster_1, cluster_id, _ = max(similar_ipmetas, key=lambda x: x[2])
                    condition = self.df['ip_obj'].apply(lambda x: x.ip == ipmeta.ip)
                    self.df.loc[condition, 'cluster_id'] = cluster_id                   
                    assign_new_ipmeta_cluster_1.append(ipmeta)
                except:
                    pass

            remain = []
            for ipmeta_input in ipmeta_inputs:
                if ipmeta_input.ip not in [ipmeta_c.ip for ipmeta_c in assign_new_ipmeta_cluster_1]:
                    remain.append(ipmeta_input)

            logger.info(f"from {len(ipmeta_inputs)} ipmeta input, \
                {len(assign_new_ipmeta_cluster_1)} ipmeta input similar with db clusters, \
                    {len(remain)} ipmeta has remain ___find_similar_ip_with_other_cluster___", {"command": "find_similar_ip_with_other_cluster"})
        else:
            assign_center_ipmeta_clusters = []
            for center_ipmeta_input, similar_center_ipmetas in dict_similar_ipmeta.items():
                try:
                    best_similar_center_cluster, cluster_id, _ = max(similar_center_ipmetas, key=lambda x: x[2])
                    #self.df['cluster_id'][self.df['cluster'] == self.df['cluster'][self.df.apply(lambda x: x['ip_obj'].ip == center_ipmeta_input.ip, axis=1)].values[0]] = cluster_id                      

                    # bug
                    condition = self.df['cluster'] == self.df['cluster'][self.df['ip_obj'].apply(lambda x: x.ip == center_ipmeta_input.ip)].values[0]
                    self.df.loc[condition, 'cluster_id'] = cluster_id                      
                    assign_center_ipmeta_clusters.append(center_ipmeta_input)
                except:
                    pass
        
            remain = []
            for center_ipmeta_input in ipmeta_inputs:
                if center_ipmeta_input.ip not in [ipmeta_c.ip for ipmeta_c in assign_center_ipmeta_clusters]:
                    remain.append(center_ipmeta_input)

            logger.info(f"from {len(ipmeta_inputs)} new cluster found, \
                {len(assign_center_ipmeta_clusters)} cluster similar with db clusters, \
                {len(remain)} cluster has new ___find_similar_ip_with_other_cluster___", {"command": "find_similar_ip_with_other_cluster"})

        self.update_df()        
        return remain

    def create_cluster(self, df):
        """
        create new instance for new cluster not old.
        cluster is a number produced by dbscan model. 
        create (cluster, cluster_id).
        update df["cluster_id"]
        return df
        """
        cluster_label = set(zip(df['cluster'], df['label'], df["detection_source"], df["cluster_id"]))
        cluster_cluster_id = {}
        
        for c, l, ds, cid in cluster_label:
            if l != '-1' and cid is None:
                clus = ClusterRef.objects.create(cluster_label=l, detection_source=ds)   
                clus.save()
                cluster_cluster_id[c] = clus.id
            elif l == '-1':
                cluster_cluster_id[c] = self.cluster_id_negative
            else:
                cluster_cluster_id[c] = cid

        df['cluster_id'] = df.apply(lambda x: cluster_cluster_id[x["cluster"]] if x["cluster_id"] is None else x["cluster_id"], axis=1)    
        return df

    def save_ip(self):
        IpCluster.objects.bulk_create(self.new_ipcluster_instances)
        logger.info(f"number of new ipcluster instances: {len(self.new_ipcluster_instances)} ___save_ip___")
        
        for ipcluster in self.update_ipcluster_instances:
            ipcluster.save()
        logger.info(f"number of updated ipcluster instances: {len(self.update_ipcluster_instances)} ___save_ip___")
        
        for clusterref in self.update_clusterref_instances:
            clusterref.save()
        logger.info(f"number of updated clusterRef instances: {len(self.update_clusterref_instances)} ___save_ip___")

        IpDistance.objects.bulk_create(self.new_ip_distance_instances)
        logger.info(f"number of new IpDistance instances: {len(self.new_ip_distance_instances)} ___save_ip___")

    def append_instance(self, df): 
        clusters = df["cluster_id"].unique().tolist()
        cluster_obj = {}
        
        for cid in clusters:
            if cid is not None:
                clus_obj = ClusterRef.objects.get(id=cid, detection_source=self.detection_source)
                self.update_clusterref_instances.append(clus_obj)
                cluster_obj[cid] = clus_obj

        for index, row in df.iterrows():   
            if row["cluster_id"] is not None:
                clus = cluster_obj[row["cluster_id"]]       
                ipmeta = row["ip_obj"]   
                traffic = row['total_traffic']
                queryset = IpCluster.objects.filter(ip=ipmeta.ip, cluster=clus)
                if queryset.exists():
                    ipcluster = IpCluster.objects.get(ip=ipmeta.ip, cluster=clus)
                    ipcluster.update_counter+= 1  
                    ipcluster.traffic = traffic
                    ipcluster.note= todict(ipmeta)
                    self.update_ipcluster_instances.append(ipcluster)
                else:
                    ipcluster = IpCluster(ip=ipmeta.ip, cluster=clus, traffic=traffic,asn=ipmeta.asn, note=todict(ipmeta))
                    self.new_ipcluster_instances.append(ipcluster)

    def get_center(self, cluster_group='-1'):

        most_traffic_ip_clusters = IpCluster.objects.filter(
            updated_at__gte=self.start_date,
            updated_at__lte=self.end_date, cluster__detection_source=self.detection_source
        ).values(
            'cluster'
        ).annotate(
            total_traffic=Sum('traffic')
        ).order_by(
            '-total_traffic'
        )#.distinct(
        #     'cluster'
        # )
        
        ip_clusters = []
        
        if cluster_group == 'other':
            most_traffic_ip_clusters = most_traffic_ip_clusters.exclude( cluster__cluster_label__in=['-1'])

            for cluster_info in most_traffic_ip_clusters:
                ip_cluster = IpCluster.objects.filter(
                    cluster=cluster_info['cluster'], cluster__detection_source=self.detection_source
                ).order_by('-traffic').first()
                if ip_cluster:
                    ip_clusters.append(ip_cluster)
            logger.info(f"number of center ip cluster from db {len(ip_clusters)} ___get_center___")


        if cluster_group == '-1':
            most_traffic_ip_clusters = most_traffic_ip_clusters.filter( cluster__cluster_label__in=['-1'])
            for cluster_info in most_traffic_ip_clusters:
                ip_cluster = IpCluster.objects.filter(
                    cluster=cluster_info['cluster'],
                    update_counter__lte = self.update_counter, cluster__detection_source=self.detection_source
                ).order_by('-traffic')
                if ip_cluster:
                    ip_clusters.extend(ip_cluster)
            logger.info(f"number of negative ip from db {len(ip_clusters)} ___get_center___")

        result = {}
        for ipclus in ip_clusters:
            result[ipclus.get_ip()] = [ipclus.cluster.id, None]
        dicts = []
        if len(ip_clusters) > 0:
            try:
                for ipclus in ip_clusters:
                    note = ipclus.note.replace("tzinfo=<UTC>", "")
                    dicts.append(eval(note))
                ipMetas = dicttoIpMeta(dicts)    
            except Exception as e:
                logger.info(f"error dict to ipmeta {e}")
                gte = self.start_date.strftime("%Y-%m-%d 00:00:00")    
                lt  = self.end_date.strftime("%Y-%m-%d %H:00:00")    
                ipMetas = produce_ipmeta_clickhouse(gte=gte,lt=lt,ips=[ipclus.ip for ipclus in ip_clusters], timeframe='Daily')  # daily
        else:
            ipMetas = []    

        for ipmeta in ipMetas:
            result[ipmeta.ip][1] = ipmeta
        
        new_result = {}
        for key, row in result.items():
            if row[1] is not None:
                new_result[key] = row
        
        logger.info(f"number of ipmetas, output of get center:  {len(new_result.keys())} ___get_center___")
        
        return new_result 

    def remove_negative_rows(self, ips ):
        instances_to_delete = IpCluster.objects.filter(ip__in=ips, cluster__id= self.cluster_id_negative)
        instances_to_delete.delete()
        logger.info(f"number of old negative ipcluster to delete: {len(ips)} ___remove_negative_rows___")

    def searching_duplicate_ip(self):
    
        all_querysets = IpCluster.objects.filter(ip__in=[ipmeta.ip for ipmeta in self.df['ip_obj'].tolist()], cluster__detection_source=self.detection_source)

        dict_query_set = {}
        for queryset in all_querysets:
            if dict_query_set.get(queryset.ip) == None:
                dict_query_set[queryset.get_ip()] = [queryset]
            else:
                dict_query_set[queryset.get_ip()].append(queryset)

        for ipmeta_input in self.df['ip_obj']:
            queryset = dict_query_set.get(ipmeta_input.ip)
            if queryset is not None:
                try:
                    if len(queryset) == 1:
                        ipmeta_db = dicttoIpMeta([eval(queryset[0].note.replace("tzinfo=<UTC>", ""))])[0]
                        sim = self.model.predict({'ipmeta1': ipmeta_db, 'ipmeta2': ipmeta_input, 'prob_flag':True, 'fast':False})
                        if sim > 0.5:
                            condition = self.df["ip_obj"].apply(lambda x: x.ip ==  ipmeta_input.ip)
                            self.df.loc[condition, 'cluster_id'] = queryset[0].cluster_id
                    elif len(queryset) > 1:
                        ipmeta_db_list = []
                        for i in range(len(queryset)):
                            ipmeta_db = dicttoIpMeta([eval(queryset[i].note.replace("tzinfo=<UTC>", ""))])[0]
                            sim = self.model.predict({'ipmeta1': ipmeta_db, 'ipmeta2': ipmeta_input, 'prob_flag':True, 'fast':False})
                            if sim > 0.5:
                                ipmeta_db_list.append((queryset[i].cluster_id, sim))
                        best_cluster_id = max(ipmeta_db_list, key=lambda x: x[1])[0] if len(ipmeta_db_list) > 0 else None
                        condition = self.df["ip_obj"].apply(lambda x: x.ip ==  ipmeta_input.ip)
                        self.df.loc[condition, 'cluster_id'] = best_cluster_id
                    else: pass
                except Exception as e:
                    print(e, ipmeta_input)
            else:
                pass

        self.update_df()

    def create_distance_matrix_with_db_pairs(self,ipmetas):
        matrix_existed_elems, non_existed_pairs = self.generate_pairs_with_distance(instances=ipmetas)
        
        m = Multiprocessing()
        res = m.base_calalculate_parallel(model=self.model,data=non_existed_pairs, processor_number=self.processor_number, func_name='cal_dist_parallel')

        res_flat = []
        for chunk in res:
            res_flat.extend(chunk)
        
        res.clear()
        matrix_existed_elems.extend(res_flat)
        res_flat.clear()

        num_instances = len(ipmetas)
        distance_matrix = np.zeros((num_instances, num_instances))
        
        for dist, index in  matrix_existed_elems:
            i = index[0]
            j = index[1]
            distance_matrix[i, j] = dist
            distance_matrix[j, i] = dist
        matrix_existed_elems.clear()

        self.add_new_pair_ips_distnce(non_existed_pairs, distance_matrix)
        non_existed_pairs.clear()
        return distance_matrix

    def generate_pairs_with_distance(self,instances):
        """
        instances: list of ipmetas
        return list of [ipemta_i,ipmeta_j, distance_or_None]
        """
        # Generate all possible pairs of ips from the list with thier related indexes
        all_pairs_index = zip(combinations(instances, 2), combinations(range(len(instances)), 2))
        

        # Query the database to fetch existing pair's ips.
        ips_list = [ip.ip for ip in instances]
        queryset = IpDistance.objects.filter(ip1__in=ips_list, ip2__in=ips_list, created_at__gte=self.start_date,
                created_at__lte=self.end_date)
        existing_pairs = {
            (obj.get_ip(obj.ip1), obj.get_ip(obj.ip2)): obj.distance 
            for obj in queryset
        }
        
        matrix_existed_elems =[]
        non_existed_pairs = []
        for pair,index in all_pairs_index:
            dist=None
            if (pair[0].ip, pair[1].ip) in existing_pairs or (pair[1].ip, pair[0].ip)  in existing_pairs:
                dist = existing_pairs.get((pair[0].ip, pair[1].ip), (pair[1].ip, pair[0].ip)) 
                if type(dist) == tuple:
                    dist = existing_pairs.get(dist, None)
            if dist is None:
                non_existed_pairs.append([pair[0],pair[1],index[0], index[1]])
            else:            
                matrix_existed_elems.append((dist, index))        
        
        existing_pairs.clear()

        return matrix_existed_elems, non_existed_pairs

    def add_new_pair_ips_distnce(self,ip_index, matrix):
        for row in ip_index:
            distance = matrix[row[2],row[3]]
            instance   = IpDistance(ip1=row[0].ip,ip2=row[1].ip ,distance=distance)
            self.new_ip_distance_instances.append(instance)
            # con = IpDistance.objects.filter(ip1=row[0].ip,ip2=row[1].ip).exists()
            # if not con:
            #     instance   = IpDistance(ip1=row[0].ip,ip2=row[1].ip ,distance=distance)
            #     self.new_ip_distance_instances.append(instance)


class Multiprocessing:

    @classmethod
    def base_calalculate_parallel(cls, model, data, processor_number, func_name, args_dict=None):

        #chunk_size = len(data) // processor_number        
        chunks = chunking_data(data, processor_number)
        cls.model = model
        cls.dict_ipmeta = args_dict
        pool_func = getattr(cls, func_name)
        with Pool(processor_number) as p:
            res = p.map(func=pool_func, iterable=chunks)
        return res

    @classmethod
    def cal_dist_parallel(cls, chunks):
        result_list = []
        for chunk in chunks:        
            result_list.append((1 - cls.model.predict({'ipmeta1': chunk[0], 'ipmeta2': chunk[1], 'prob_flag': True, 'fast': True}), (chunk[2], chunk[3])))
        chunks.clear()
        return result_list

    @classmethod
    def calculate_sim_1_parallel(cls, chunks):
        dict_similar_ipmeta = {}        
        for ipmeta_input in chunks:            
            for ipmeta_cluster in cls.dict_ipmeta.values():
                sim = cls.model.predict({'ipmeta1': ipmeta_cluster[1], 'ipmeta2': ipmeta_input, 'prob_flag': False, 'fast': True})
                if int(sim) == 1:
                    if dict_similar_ipmeta.get(ipmeta_input) is None:
                        dict_similar_ipmeta[ipmeta_input] = [ipmeta_cluster[1]]
                    else:
                        dict_similar_ipmeta[ipmeta_input].append(ipmeta_cluster[1])
                else:
                    if dict_similar_ipmeta.get(ipmeta_input) is None:
                        dict_similar_ipmeta[ipmeta_input] = []
                    else:
                        pass
        return(dict_similar_ipmeta)

    @classmethod    
    def calculate_sim_others_parallel(cls, chunks):
        dict_similar_ipmeta = {}
        for ipmeta_input in chunks:
            for ipmeta_cluster in cls.dict_ipmeta.values():              
                sim = cls.model.predict({'ipmeta1': ipmeta_cluster[1], 'ipmeta2': ipmeta_input, 'prob_flag': True, 'fast': True})
                if sim > 0.5:
                    if dict_similar_ipmeta.get(ipmeta_input) is None:
                        dict_similar_ipmeta[ipmeta_input] = [(ipmeta_cluster[1], ipmeta_cluster[0], sim)]
                    else:
                        dict_similar_ipmeta[ipmeta_input].append((ipmeta_cluster[1], ipmeta_cluster[0], sim))
                else:
                    if dict_similar_ipmeta.get(ipmeta_input) is None :
                        dict_similar_ipmeta[ipmeta_input] = []
                    else:
                        pass
        return(dict_similar_ipmeta)
    
    @classmethod
    def initiate_other(cls, chunks):
        other_ip = []
        for ipmeta in chunks:    
            ip = pickle.loads(ipmeta)
            isOTHER = True
            for detect in ip.detection_dist:
                if detect.detection in ('27459p','28392m'):
                    isOTHER = False
                    break
            if isOTHER == True:
                other_ip.append(ip)
        
        chunks.clear()
        return(other_ip)

    @classmethod
    def initiate_freeze(cls, chunks):
        freeze_ip = []
        for ipmeta in chunks:    
            ip = pickle.loads(ipmeta)
            isFreeze = False
            for detect in ip.detection_dist:
                if detect.detection in ('27459p'):
                    isFreeze = False
                    break
                if detect.detection in ('28392m'):
                    isFreeze = True
            if isFreeze == True:
                freeze_ip.append(ip)
        
        chunks.clear()
        return(freeze_ip)

    @classmethod
    def initiate_Iran(cls, chunks):
        Iran_ip = []
        for ipmeta in chunks:    
            ip = pickle.loads(ipmeta)
            isIran = False
            for detect in ip.detection_dist:
                if detect.detection in ('27459p'):
                    isIran = True
                if detect.detection in ('28392m'):
                    isIran = False
                    break

            if isIran == True:
                Iran_ip.append(ip)
        
        chunks.clear()
        return(Iran_ip)            
