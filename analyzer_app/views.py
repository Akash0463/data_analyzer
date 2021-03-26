from django.shortcuts import render
import pandas as pd
import psycopg2
from sqlalchemy import create_engine
import numpy as np
from collections import defaultdict
from datetime import datetime
from psycopg2 import sql
import matplotlib.pyplot as plt
import io
import urllib, base64


df =""
df1 = ""
conn = None
cursor = None
vul_per_host_dict = {}
count_list = []
engine = None

def connection():
    global conn, cursor, engine
    engine = create_engine('postgresql://postgres:12345@localhost:5432/SampleDB')
    conn = psycopg2.connect("host=localhost dbname=SampleDB user=postgres password=12345")
    conn.autocommit = True
    cursor = conn.cursor()


def home(request):
    connection()
    return render(request,'apply.html')

def displayFile(request):
    head = list(df.columns)

    df1 = pd.DataFrame(df)

    data = df1.to_numpy()
    
    head_len = len(head)
    
    return render(request,'displayFile.html',{'head':head,'data':data, 'range':range(head_len)})

def updateFile(request):
    return render(request,'apply.html')

def saveData(request):
    selected_col = request.POST.getlist('checkval')

    list1 = list(df.columns)

    list2 = set(list1) - set(selected_col)
    final_list = list(list2)

    data = df.drop(final_list,axis=1)

    today = datetime.now()
    date_time = today.strftime("%d/%m/%Y-%H:%M:%S")
    date_now = today.strftime("%Y-%m-%d")

    tableName = "network_scan"+date_time

    cursor.execute("INSERT INTO network_scan_table VALUES (%s,%s)",(tableName,date_now,))

    data.to_sql(tableName, engine)
    return render(request,'apply.html')   


def show_file_details(request):
    global df
    data_file = request.FILES['myfile']
    df = pd.read_csv(data_file)
    head = list(df.columns)
    column_len = len(head)

    context = {'ftype' : data_file, 'columns':head, 'column_len':column_len}
    return render(request, 'file_details.html',context)

def showChart(request):
    column = list(df.columns)
    return render(request,'chart.html',{'column':column})

def showOptions(request):
    return render(request,'options.html')

def showUniqueIPs(request,pk):
    global vul_per_host_dict, count_list
    total_vul_cnt = 0
    total_high_cnt = 0
    total_critical_cnt = 0
    total_low_cnt = 0
    total_medium_cnt = 0
    total_none_cnt = 0
    context ={}

    vul_per_host = list()
    ports_without_zero = list()
    vul_per_host_dict = defaultdict(list)
    vul_ports_per_host = {}
   
    col_val = df[["Host"]].values
    ip_list = np.unique(col_val)
    ip_len = len(ip_list)

    vul_port = df[["Port"]].values
    vul_port_list = np.unique(vul_port)
    vul_port_len = len(vul_port_list)

    for ip in ip_list:
        sum = (df.Host == ip).sum()
        vul_per_host.append(sum)
        total_vul_cnt = total_vul_cnt + sum

    for i in range (0,ip_len):
        vul_per_host_dict[ip_list[i]].append(vul_per_host[i])

    for ip in ip_list:
        ports_without_zero.clear()
        ports = df['Port'][df['Host']==ip].values
        ports_list = list(ports)

        for i in ports_list:
            if(i!= 0):
                ports_without_zero.append(i)

        ports_len = len(ports_without_zero)

        vul_ports_per_host[ip] = ports_len


    unique_vul = df[["Description"]].values
    unique_vul_list = np.unique(unique_vul)
    unique_vul_list_len = len(unique_vul_list)

    for ip in ip_list:
        high_count = 0
        low_count = 0
        medium_count = 0
        critical_count = 0
        none_count = 0

        ports1 = df['Risk'][df['Host']==ip].values
        ports_list1 = list(ports1)
        
        if "High" in ports_list1:
            high_count = ports_list1.count("High")
            total_high_cnt = total_high_cnt + high_count

        if "Low" in ports_list1:
            low_count = ports_list1.count("Low")
            total_low_cnt = total_low_cnt + low_count

        if "Medium" in ports_list1:
            medium_count = ports_list1.count("Medium")
            total_medium_cnt = total_medium_cnt + medium_count

        if "Critical" in ports_list1:
            critical_count = ports_list1.count("Critical")
            total_critical_cnt = total_critical_cnt + critical_count

        if "None" in ports_list1:
            none_count = ports_list1.count("None")
            total_none_cnt = total_none_cnt + none_count

        vul_per_host_dict[ip].append(critical_count)
        vul_per_host_dict[ip].append(high_count)
        vul_per_host_dict[ip].append(medium_count)
        vul_per_host_dict[ip].append(low_count)
        vul_per_host_dict[ip].append(none_count)

    count_list = [ip_len, total_vul_cnt, total_critical_cnt, total_high_cnt, total_medium_cnt, total_low_cnt, total_none_cnt]

    
    if pk == '1':
        context = {'ip_list':ip_list, 'ip_len':ip_len,'pk1':'pk1'}
 
    if pk == '2':
        context ={'vul_per_host':dict(vul_per_host_dict), 'count_list':count_list, 'pk2':'pk2'}
 
    if pk == '3':
        context = {'vul_port_list':vul_port_list, 'vul_port_len':vul_port_len,'pk3':'pk3'}
 
    if pk == '4':
        context ={'vul_ports_per_host':vul_ports_per_host,'pk4':'pk4'}
 
    if pk == '6':
        context = {'unique_vul_list':unique_vul_list, 'unique_vul_list_len':unique_vul_list_len,'pk6':'pk6'}

    if pk == '7':
        return render(request,'dateScan.html')

    return render(request,'report.html',context)

def showVulInfo(request,pk,val,dataframe):
    context = {}
    if val == "vul_cnt":
        if dataframe == "df1":
            df2 = df[(df1.Host == pk)]
        else:
            df2 = df[(df.Host == pk)]

        host_details = df2[["Host", "Risk", "Plugin ID", "CVE", "Port", "Name", "Description", "Solution"]]

        host_details_data = host_details.to_numpy()
        context = {'host_details_col':host_details, 'host_details_data':host_details_data}

    else:
        if dataframe == "df1":
            df2 = df[(df1.Risk == val) & (df1.Host == pk)]
        else:
            df2 = df[(df.Risk == val) & (df.Host == pk)]
        
        host_details = df2[["Host", "Risk", "Plugin ID", "CVE", "Port", "Name", "Description", "Solution"]]

        host_details_data = host_details.to_numpy()
        
        context = {'host_details_col':host_details, 'host_details_data':host_details_data}

    return render(request, 'showVulInfo.html',context)

def comparePreviousReports(request):
    host_col = df[["Host"]].values
    ip_list = np.unique(host_col)

    context = {'ip_list':ip_list}
    return render(request, 'compareFile.html',context)

def showCompareReport(request,pk):
    
    query = sql.SQL("SELECT * from {table}").format(table=sql.Identifier('network_scan_table'))
    cursor.execute(query)
    result = cursor.fetchall()

    port_col = df[["Port"]].values
    port_list = np.unique(port_col)
    compare_results_dict = {key:[] for key in port_list}
    tbname_list = []

    for tbname in result:
        tbname_list.append(tbname[0])
        query1 = '''select * from "{}"'''        
        compare_df = pd.read_sql_query(query1.format(tbname[0]), engine)

        ports = compare_df['Port'][compare_df['Host']==pk].values
        unique_ports = np.unique(ports)
 
        for port in unique_ports:
            filter_data = []
            data = compare_df['Name'][(compare_df.Host == pk) & (compare_df.Port == port)].to_string(index=False)
            data = data.split('\n')
            
            for element in data:
                filter_data.append(element.strip())

            compare_results_dict[port].append(filter_data)

    filtered_dict = dict((k, v) for k, v in compare_results_dict.items() if v)
    context = {'port_list':port_list, 'compare_report':dict(filtered_dict), 'tbname':tbname_list, 'host':pk}

    return render(request, 'showCompareReport.html',context)

def dateScan(request):
    unique_ip_list = []
    unique_list = []
    host_list = []
    host_dict = defaultdict(list)

    date1 = request.POST['date1']
    date2 = request.POST['date2']

    new_date1 = datetime.strptime(date1, '%Y-%m-%d').date()
    new_date2 = datetime.strptime(date2, '%Y-%m-%d').date()

    date_diff = new_date2 - new_date1

    cursor.execute("SELECT tname FROM network_scan_table WHERE tdate BETWEEN %s AND %s", (date1, date2,))
    result = cursor.fetchall()

    for tbname in result:
        query1 = '''select * from "{}"'''        
        df2 = pd.read_sql_query(query1.format(tbname[0]), engine)

        original_ip_list = df2["Host"].to_numpy()
        unique_list.append(np.unique(original_ip_list))


        for ip in original_ip_list:
            host_list.append(ip)

        for ip in host_list:
            if ip not in unique_ip_list:
                unique_ip_list.append(ip)


    for ip in unique_ip_list:
        cnt = host_list.count(ip)
        host_dict[ip].append(cnt)
        host_dict[ip].append(0)

    for row in unique_list:
        for k,v in host_dict.items():
            if k in row:
                v[1] = v[1]+1

    context = {'host_dict':dict(host_dict), 'date1':date1, 'date2':date2, 'period':date_diff.days, 'ip_list_len':len(unique_ip_list)}
    return render(request,'dateScanReport.html',context)

def Graph(request):
    plt.plot(range(10))
    fig = plt.gcf()
    buf = io.BytesIO()
    fig.savefig(buf,format='png')
    buf.seek(0)
    string = base64.b64encode(buf.read())
    uri = urllib.parse.quote(string)
    return render(request, 'showGraph.html', {'data':uri})

def showGraph(request):
    vul_port = df[["Host"]].values
    vul_port_list = np.unique(vul_port)
    print(vul_port_list)
    port_len = len(vul_port_list)
    print(port_len)

    vul_per_host = list()
    total_vul_cnt = 0
    col_val = df[["Host"]].values
    ip_list = np.unique(col_val)
    for ip in ip_list:
            sum = (df.Host == ip).sum()
            vul_per_host.append(sum)
            total_vul_cnt = total_vul_cnt + sum
        
    print(vul_per_host)

    fig = plt.figure(figsize =(10, 7)) 
    #plt.pie(vul_per_host, labels = vul_port_list) 
    # Wedge properties 
    wp = { 'linewidth' : 1, 'edgecolor' : "green" } 

    col_val = df[["Host"]].values
    ip_list = np.unique(col_val)
    ip_len = len(ip_list)
    tuple_list = []

    for ip in ip_list:
        tuple_list.append(0.1)

    t1 = tuple(tuple_list)

    explode = t1
    
    print(explode)
    
    # Creating autocpt arguments 
    def func(pct, allvalues): 
        absolute = int(pct / 100.*np.sum(allvalues)) 
        return "{:.1f}%\n({:d})".format(pct, absolute) 
    
    # Creating plot 
    fig, ax = plt.subplots(figsize =(25, 12)) 
    wedges, texts, autotexts = ax.pie(vul_per_host,  
                                    autopct = lambda pct: func(pct, vul_per_host), 
                                    explode = explode,  
                                    labels = vul_port_list, 
                                    #shadow = True, 
                                    #colors = colors, 
                                    startangle = 90, 
                                    wedgeprops = wp, 
                                    textprops = dict(color ="black")) 
    
    # Adding legend 
    ax.legend(wedges, vul_port_list, 
            title ="Hosts", 
            loc ="lower left", 
            bbox_to_anchor =(1, 0, 0.5, 1)) 
    
    plt.setp(autotexts, size = 8, weight ="bold") 
    ax.set_title("Pie chart")

    plt.savefig('media/peichart.png',dpi=100)
    return render(request,'showGraph.html')