"""URL patterns for the memprobe webapp."""

from django.urls import path
from . import views

urlpatterns = [
    # Crawler / SEO
    path('sitemap.xml',                       views.sitemap,              name='sitemap'),
    path('robots.txt',                        views.robots,               name='robots'),

    # Public pages
    path('',                                  views.landing,              name='landing'),
    path('login',                             views.login_view,           name='login'),
    path('logout',                            views.logout_view,          name='logout'),
    path('privacy',                           views.privacy,              name='privacy'),
    path('terms',                             views.terms,                name='terms'),
    path('docs',                              views.docs,                 name='docs'),
    path('pricing',                           views.pricing,              name='pricing'),

    # Account self-service
    path('account/delete',                    views.delete_account,       name='delete_account'),

    # Protected app
    path('app',                               views.index,                name='index'),
    path('app/',                              views.index,                name='index_slash'),

    # Protected API
    path('api/analyze',                       views.api_analyze,          name='api_analyze'),
    path('api/jobs/<str:job_id>',             views.api_job_status,       name='api_job_status'),
    path('api/diff',                          views.api_diff,             name='api_diff'),
    path('api/history',                       views.api_history,          name='api_history'),
    path('api/history/trend',                 views.api_history_trend,    name='api_history_trend'),
    path('api/history/<int:build_id>',        views.api_history_build,    name='api_history_build'),
    path('api/history/<int:build_id>/delete', views.api_history_delete,   name='api_history_delete'),
    path('api/history/<int:build_id>/patch',  views.api_history_patch,    name='api_history_patch'),
    path('api/compare',                       views.api_compare,          name='api_compare'),
    path('api/projects',                      views.api_projects,         name='api_projects'),
    path('api/project-summaries',             views.api_project_summaries, name='api_project_summaries'),
    path('api/projects-full',                 views.api_projects_full,    name='api_projects_full'),
    path('api/project/<str:project_name>',    views.api_project_detail,   name='api_project_detail'),
    path('api/share',                         views.api_share,            name='api_share'),

    # Public share
    path('s/<str:share_id>',                  views.share_view,           name='share_view'),
]
