import logging
import secrets
import warnings
from typing import List

import matplotlib.pyplot as plt
import numpy as np
from pyvis.network import Network
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics import silhouette_score
from tqdm import tqdm

from .distance import Utils as dis
from utils.ipmeta.classes import IpMeta
from utils.ipmeta.main import produce_ipmeta

logger = logging.getLogger("ip_classification.ip_clustering")


class Clustering:
    @classmethod
    def random_color_generator(cls):
        """create new color for visualization 
        Return:
            Str: Return hexadecimal of random color created.
        """
        color = "#" + ''.join([secrets.choice('0123456789ABCDEF') for j in range(6)])
        return color

    @classmethod
    def calculate_dist_matrix(cls, ip_list_objs, in_metric):
        """It will create distance matrix for all input ips.
        Matrix will be Triangular because dist(i,j)=dist(j,i)
        Args:
            ip_list_objs: list of IpMeta ip objects.
            in_metric: metric for distance calculation.
        Returns:
            Numpy array: matrix of distances.        
        """
        ip_list_len = len(ip_list_objs)
        ips_numpy_array = np.empty(shape=(ip_list_len, ip_list_len, 1))
        ips_numpy_array.fill(-1)
        for ip_i in tqdm(ip_list_objs, desc='Calculating distance matrix:'):
            ip_i.nearest = {}
            ip_i.farest = {}
            index_i = ip_list_objs.index(ip_i)
            for ip_j in ip_list_objs:
                index_j = ip_list_objs.index(ip_j)
                if index_i <= index_j:
                    if ip_i.ip == ip_j.ip:
                        ips_numpy_array[index_i, index_j] = np.zeros(1)
                    elif ips_numpy_array[index_i][index_j] == -1:
                        temp_dist = dis.get_distance(ip_i, ip_j, in_metric)[in_metric]
                        ips_numpy_array[index_i, index_j], ips_numpy_array[index_j, index_i] = temp_dist, temp_dist

                        if temp_dist < 0.2:
                            ip_i.nearest[index_j] = temp_dist

                        if temp_dist > 2:
                            ip_i.farest[index_j] = temp_dist

            nearest_key_count = len(ip_i.nearest.keys())
            farest_key_count = len(ip_i.farest.keys())

            if nearest_key_count >= 1:
                for key1, val1 in ip_i.nearest.items():
                    # for nearest
                    if nearest_key_count > 1:
                        for key2, val2 in ip_i.nearest.items():
                            if key1 != key2:
                                ips_numpy_array[key1][key2] = (val1 + val2) / 2
                                ips_numpy_array[key2][key1] = (val1 + val2) / 2
                    # for farest
                    if farest_key_count >= 1:
                        for key2, val2 in ip_i.farest.items():
                            if key1 != key2:
                                ips_numpy_array[key1][key2] = val2
                                ips_numpy_array[key2][key1] = val2

        return ips_numpy_array

    @classmethod
    def agglom_clustering(cls, in_dist_matrix: list, num):
        """Agglomerative clustering for input distance matrix.
        Args:
            in_dist_matrix: distance numpy array distance.
            num: number of clusters.
        Returns:
            List: return cluster labels.
        """
        temp_lables = []
        for i in tqdm(num, desc='Clustering:'):
            clustering = AgglomerativeClustering(n_clusters=i, linkage='average').fit(in_dist_matrix)
            # ac_list = [(AgglomerativeClustering(n_clusters = i)).labels_ for i in k]
            temp_lables.append(clustering.labels_)

        return temp_lables

    @classmethod
    def calculate_silh(cls, in_dist_matrix, in_lables, num):
        """Calculate silhouette score for all the clusters.
        Args:
            in_dist_matrix: distance mitrix.
            in_labels(Nested List): each ip label for all number of clusters.
            num: range for clusters.
        Returns:
            Dict: key-> cluster number, value-> cluster score
        """
        temp_scores = {}
        for i, j in enumerate(tqdm(num, desc='Calculate silh:')):
            temp_scores[j] = silhouette_score(in_dist_matrix, in_lables[i])

        return temp_scores

    @classmethod
    def plot_silh_values(cls, in_scores, num):
        """ plot score for input values
        Args:
            in_scores: input score dict.
        """
        y = list(in_scores.values())
        plt.bar(num, y)
        plt.xlabel('Number of clusters', fontsize=20)
        plt.ylabel('Sil(i)', fontsize=20)
        plt.show()

    @classmethod
    def visualize_list(cls, in_list, cluster_label, cluster_num, in_metric):
        """It will visualize input ip list.
        Args:
            in_ip_list: List of ip objects.
            in_List: list of ip.
            cluster_label: label for each ip.
            cluster_num: Number of clusters.
        Returns:
            Visualize all ips to .html file with pyvis library.
        """
        color_list = []
        got_net = Network(height='100%', width='100%', bgcolor='#222222', font_color='white')
        got_net.force_atlas_2based()
        # got_net.barnes_hut()

        for idx in tqdm(range(1, cluster_num + 1), desc='Visualizing input IPs'):
            temp_color = cls.random_color_generator()
            while True:
                if temp_color in color_list or temp_color in ['#000000', '#FFFFFF']:
                    temp_color = cls.random_color_generator()
                else:
                    break
            color_list.append(temp_color)

            got_net.add_node(idx, idx, color=temp_color)

        for index, ip in enumerate(in_list):
            temp_value = cluster_label[index]
            got_net.add_node(ip, ip, color=color_list[temp_value])
            got_net.add_edge(ip, temp_value + 1, color=color_list[temp_value])

        got_net.get_adj_list()
        got_net.show(in_metric + '.html')

    # @classmethod
    # def process_func(cls):
    #     st_process = subprocess.Popen(['streamlit', 'run', 'streamlit_test.py'], shell=True, stdout=PIPE, stderr=PIPE)
    #     return st_process
    #     # print(st_process)
    #     # print(st_process.stdout)

    @classmethod
    def print_clusters(cls, in_ips, in_labels):
        clusters = {}
        for idx, value in enumerate(in_labels):
            clusters.setdefault(value + 1, []).append(in_ips[idx])
        return clusters    

    @classmethod
    def get_clustering(cls, ip_list, in_metric):
        # Run streamlit app
        # proc = subprocess.Popen(['streamlit', 'run', 'streamlit_test.py'], text= True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # try:
        # except:
        #     pass
        # streamlit.cli._main_run('streamlit_test.py')

        ip_list_len = len(ip_list)
        temp_ips = []
        for ip_obj in ip_list:
            temp_ips.append(ip_obj)
        ips_np_arr = Clustering.calculate_dist_matrix(ip_list, in_metric)
        nsamples, nx, ny = ips_np_arr.shape

        reshaped_dist_matrix = ips_np_arr.reshape(nsamples, nx * ny)

        # clustering = AgglomerativeClustering(6).fit(d2_train_dataset)

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore")

            k = range(2, int(ip_list_len))
            clustering_labels = Clustering.agglom_clustering(reshaped_dist_matrix, k)

            # Appending the silhouette scores
            silh_scores = {}
            silh_scores.fromkeys(k)
            silh_scores = Clustering.calculate_silh(reshaped_dist_matrix, clustering_labels, k)
            best_cluster_number = max(silh_scores, key=silh_scores.get)

            # Plotting
            # Clustering.plot_silh_values(silh_scores, k)

            lables = clustering_labels[best_cluster_number - 2]
            # Clustering.visualize_list(temp_ips, lables.tolist(), best_cluster_number, in_metric)

            res = Clustering.print_clusters(temp_ips, lables)
            return res


if __name__ == '__main__':
    ips = ['185.48.242.160', '185.48.241.161', '31.13.92.51', '185.60.216.52', '185.48.240.161', '157.240.227.63',
           '94.20.240.32', '85.132.68.226', '46.162.220.160', '157.240.9.52', '157.240.20.63', '94.20.255.227',
           '178.160.243.35', '157.240.236.63', '185.48.241.162', '212.73.83.97', '185.60.216.53', '85.132.68.34',
           '85.132.127.33', '185.166.104.95', '85.132.68.163', '31.13.86.52', '31.13.92.52', '188.0.241.33',
           '212.73.83.33', '157.240.227.60', '157.240.203.63', '185.48.242.161', '179.60.192.52', '178.160.243.99',
           '157.240.21.63', '188.0.241.27', '94.20.240.35', '62.212.252.225', '185.48.240.162', '85.132.127.34',
           '46.162.220.163', '157.240.236.60', '94.20.255.228', '85.132.68.224', '94.20.255.163', '157.240.20.52',
           '85.132.68.160', '185.147.179.120', '85.132.68.33', '31.13.86.51', '157.240.203.60', '185.147.178.15',
           '179.60.192.51', '185.60.218.52', '212.73.83.98', '157.240.9.53', '212.73.83.34', '157.240.21.52',
           '185.166.104.4', '185.147.179.108', '5.106.10.157', '94.20.255.160', '5.106.10.154', '152.199.20.86',
           '157.240.234.63', '185.166.104.3', '142.250.180.42', '91.229.46.3', '212.33.193.28', '212.33.193.8',
           '185.147.179.147', '142.250.185.42', '188.0.241.9', '185.4.3.30', '178.160.243.36', '185.147.179.166',
           '172.217.18.138', '185.147.179.165', '188.0.241.4', '185.147.179.109', '185.143.233.5', '74.125.98.39',
           '157.240.27.63', '172.217.18.132', '212.33.193.77', '5.106.10.156', '5.106.10.155', '5.106.10.158',
           '185.147.179.231', '5.106.10.159', '212.33.193.70', '5.106.10.160', '89.45.51.142', '91.229.46.5',
           '74.125.98.8', '185.143.234.5', '178.160.243.100', '185.107.32.120', '172.217.169.234', '216.58.209.138',
           '185.147.179.215', '74.125.98.6', '91.229.46.8']
    ip_list: List[IpMeta] = produce_ipmeta('2022-01-23', '2022-02-23', ips)
    distance_metric = 'dns_dist'
    Clustering.get_clustering(ip_list, distance_metric)
