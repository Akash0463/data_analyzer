from django.contrib import admin
from django.urls import path
from . import views


urlpatterns = [
    path('', views.home, name='home'),
    path('displayFile', views.displayFile, name='displayFile'),
    path('updateFile', views.updateFile, name='updateFile'),
    path('saveData', views.saveData, name='saveData'),
    path('show_file_details', views.show_file_details, name='show_file_details'),
    path('showChart', views.showChart, name='showChart'),
    path('showOptions', views.showOptions, name='showOptions'),
    path('showUniqueIPs<str:pk>', views.showUniqueIPs, name='showUniqueIPs'),
    path('showVulInfo<str:pk>/<str:val>/<str:dataframe>', views.showVulInfo, name='showVulInfo'),
    path('comparePreviousReports', views.comparePreviousReports, name='comparePreviousReports'),
    path('showCompareReport<str:pk>', views.showCompareReport, name='showCompareReport'),
    path('dateScan', views.dateScan, name='dateScan'),
    path('dateScan1', views.dateScan1, name='dateScan1'),
    path('showGraph<str:pk>', views.showGraph, name='showGraph'),
    path('missing_ip_report<str:pk>', views.missing_ip_report, name='missing_ip_report'),
    path('new_network', views.newCompanyNetwork, name='new_network'),
    path('view_file_content', views.view_file_content, name='view_file_content'),
    path('display_duplicate_vul<str:ip>', views.display_duplicate_vul, name='display_duplicate_vul'),
]