/*
 *  mul_nbapi.c: NBAPI application (c part) for MUL Controller
 *  Copyright (C) 2012-2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com> 
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include "mul_nbapi.h"
#include "mul_nbapi_statistics.h"
#include <curl/curl.h>

#define NBAPI_DP_EVENTS (C_DP_REG | C_DP_UNREG | C_PACKET_IN | C_PORT_CHANGE)

extern struct mul_app_client_cb nbapi_app_cbs;

static void
mul_core_service_conn_event(void *service UNUSED, unsigned char conn_event)
{
    c_log_info("%s: %d", FN, conn_event);
}

static void
mul_route_service_conn_event(void *service UNUSED, unsigned char conn_event)
{
    c_log_info("%s: %d", FN, conn_event);
}

static void
mul_tr_service_conn_event(void *service UNUSED, unsigned char conn_event)
{
    c_log_info("%s: %d", FN, conn_event);
}

static void
mul_fab_service_conn_event(void *service UNUSED, unsigned char conn_event)
{
    c_log_info("%s: %d", FN, conn_event);
}

static void
mul_makdi_service_conn_event(void *service UNUSED, unsigned char conn_event)
{
    c_log_info("%s: %d", FN, conn_event);
}

static void
send_request(void *gui_server, void *message)
{
    char url[512];
    CURL *curl;
    CURLcode res;

    sprintf(url, "http://%s/notification/notify",(char *)gui_server);
    c_log_info("send_request to  %s",url); 
    curl = curl_easy_init();

    sprintf(url, "http://%s/notification/notify",(char *)gui_server);
    c_log_info("send_request to  %s",url); 
 
    if (curl){
	    curl_easy_setopt(curl, CURLOPT_URL, url);
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char *)message);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen((char *)message));
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1);
    	res = curl_easy_perform(curl);
	    res = curl_easy_perform(curl);
        if(CURLE_OK != res) {
            c_log_debug("Error: %s\n", strerror(res));
        }

        curl_easy_cleanup(curl);
    }
    c_log_info("%s, %s", url, (char *)message);
}

static void
nbapi_switch_add(mul_switch_t *sw)
{
    char message[512];

    set_port_stats(sw->dpid, true);
    sprintf(message, "{dpid:'0x%llx',notification:'NOTIFICATION'}",
			U642ULL(sw->dpid));
    if(gui_server_list){
	    g_slist_foreach(gui_server_list, 
		            (GFunc)send_request, (void *)message);
    }
//    c_log_info("%s: ", FN);
    return;
}

static void
nbapi_switch_del(mul_switch_t *sw)
{
    char message[512];
    sprintf(message, "{dpid:'0x%llx',notification:'NOTIFICATION'}",
			U642ULL(sw->dpid));
//    c_log_info("%s: ", FN);
    if(gui_server_list){
        g_slist_foreach(gui_server_list, 
                (GFunc)send_request, (void *)message);
    }
    return;
}
static void
nbapi_port_add(mul_switch_t *sw, mul_port_t *port)
{
    char message[512]; 
    sprintf(message, "{dpid:'0x%llx',port:'%lu',notification:'NOTIFICATION'}",
            U642ULL(sw->dpid), U322UL(port->port_no));
//    c_log_info("%s: ", FN);
    if(gui_server_list){
        g_slist_foreach(gui_server_list, 
                (GFunc)send_request, (void *)message);
    }
    return;
}

static void
nbapi_port_del(mul_switch_t *sw, mul_port_t *port)
{
    char message[512]; 
    sprintf(message, "{dpid:'0x%llx',port:'%lu',notification:'NOTIFICATION'}",
            U642ULL(sw->dpid), U322UL(port->port_no));
//    c_log_info("%s: ", FN);
    if(gui_server_list){
        g_slist_foreach(gui_server_list,
                (GFunc)send_request, (void *)message);
    }
    return;
}

static void
nbapi_core_closed(void)
{
    c_log_info("%s: ", FN);
    if (gui_server_list) {
        g_slist_foreach(gui_server_list,
                (GFunc)send_request, "{}");
    }
    return;
}

static void
nbapi_core_reconn(void)
{
    c_log_info("%s: ", FN);
    mul_register_app_cb(NULL, NBAPI_APP_NAME,
                        C_APP_ALL_SW, NBAPI_DP_EVENTS,
                        0, NULL, &nbapi_app_cbs);
}

struct mul_app_client_cb nbapi_app_cbs = {
    .switch_add_cb =  nbapi_switch_add,
    .switch_del_cb = nbapi_switch_del,
    .switch_port_add_cb = nbapi_port_add,
    .switch_port_del_cb = nbapi_port_del,
    .core_conn_closed = nbapi_core_closed,
    .core_conn_reconn = nbapi_core_reconn
};

static bool
nbapi_service_ka(void *serv_arg UNUSED)
{
    return true;
}

static void
nbapi_timer_cb(evutil_socket_t fd UNUSED,
               short event UNUSED,
               void *arg UNUSED)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
#define NBAPI_SERVICE_LEN 4
    mul_service_t *serv_arr[NBAPI_SERVICE_LEN];
    mul_service_t *service = NULL;
    int i = 0;
    struct timeval tv = { MUL_NB_TIMEO, 0 };

    return;

    serv_arr[0] = nbapi_app_data->mul_service;
    serv_arr[1] = nbapi_app_data->tr_service;
    serv_arr[2] = nbapi_app_data->fab_service;
    serv_arr[3] = nbapi_app_data->makdi_service;

    c_wr_lock(&nbapi_app_data->lock);
    for (i = 0; i < NBAPI_SERVICE_LEN; i++) {
        service = serv_arr[i];

        if (!service) continue;

        if (service->conn.dead || service->ext_ka_flag)
            continue;

        b = of_prep_msg(sizeof(*cofp_auc), C_OFPT_AUX_CMD, 0);

        cofp_auc = (void *)(b->data);
        cofp_auc->cmd_code = htonl(C_AUX_CMD_ECHO);

        c_service_send(service, b);
        b = c_service_wait_response(service);
        if (b) {
            free_cbuf(b);
            service->ext_ka_flag = 0;
        } else {
            service->ext_ka_flag = 1;
        }
    }
    c_wr_unlock(&nbapi_app_data->lock);

    evtimer_add(nbapi_app_data->nbapi_timer_event, &tv);
}

/**
 * nbapi_module_init -
 *
 * NBAPI application entry point
 */
void
nbapi_module_init(void *base_arg)
{
    struct event_base *base = base_arg;
    struct timeval tv = { MUL_NB_TIMEO, 0 };
    
    c_log_debug("%s", FN);

    nbapi_app_data = calloc(1, sizeof(nbapi_struct_t));
    assert(nbapi_app_data);

    c_rw_lock_init(&nbapi_app_data->lock);
    nbapi_app_data->base = base;

    nbapi_app_data->mul_service = 
        mul_app_get_service_notify_ka(MUL_CORE_SERVICE_NAME,
                                   mul_core_service_conn_event,
                                   nbapi_service_ka, false, NULL);
    if (nbapi_app_data->mul_service == NULL) {
        c_log_err("%s: Mul core service instantiation failed", FN);
    }

    nbapi_app_data->route_service =
        mul_app_get_service_notify_ka(MUL_ROUTE_SERVICE_NAME,
                                   mul_route_service_conn_event,
                                   nbapi_service_ka, false, NULL);
    if (nbapi_app_data->route_service == NULL) {
        c_log_err("%s:  Mul route service instantiation failed", FN);
    }
    nbapi_app_data->fab_service =
        mul_app_get_service_notify_ka(MUL_FAB_CLI_SERVICE_NAME,
                                   mul_fab_service_conn_event,
                                   nbapi_service_ka, false, NULL);
    if (nbapi_app_data->fab_service == NULL) {
        c_log_err("%s:  Mul fab service instantiation failed", FN);
    }

    nbapi_app_data->tr_service =
        mul_app_get_service_notify_ka(MUL_TR_SERVICE_NAME,
                                   mul_tr_service_conn_event,
                                   nbapi_service_ka, false, NULL);
    if (nbapi_app_data->tr_service == NULL) {
        c_log_err("%s:  Mul traffic-routing service instantiation failed", FN);
    }

    nbapi_app_data->makdi_service =
        mul_app_get_service_notify_ka(MUL_MAKDI_SERVICE_NAME,
                                   mul_makdi_service_conn_event,
                                   nbapi_service_ka, false, NULL);
    if (nbapi_app_data->makdi_service == NULL) {
        c_log_err("%s:  Mul makdi service instantiation failed", FN);
    }

    mul_register_app_cb(NULL, NBAPI_APP_NAME,
                        C_APP_ALL_SW, NBAPI_DP_EVENTS,
                        0, NULL, &nbapi_app_cbs);

    nbapi_app_data->nbapi_timer_event = evtimer_new(base,
                                                    nbapi_timer_cb,
                                                    nbapi_app_data);
    if (nbapi_app_data->nbapi_timer_event) {
        evtimer_add(nbapi_app_data->nbapi_timer_event, &tv);
    }

    return;
}

module_init(nbapi_module_init);
