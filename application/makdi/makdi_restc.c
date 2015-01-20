/*
 *  makdi_rest.c: makdi rest client
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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
#include "config.h"
#include "mul_common.h"
#include "makdi.h"

extern makdi_hdl_t *makdi_hdl;


CURL* rest_get(CURL* curl, char *url) {
	curl = curl_easy_init();
	int len = 0;
	struct curl_slist *headers = NULL;
	/* First set the URL that is about to receive our POST. This URL can
	 just as well be a https:// URL if that is what should receive the
	 data. */
	curl_easy_setopt(curl, CURLOPT_URL, url);
	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "charsets: utf-8");
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	return curl;
}

int
service_chain_db_resync()
{
    CURL *curl;
    CURLcode res;
	char* url = "http://localhost:8181/1.0/servicech/sync";

    curl = rest_get(curl, url);
    res = curl_easy_perform(curl);
    printf("\nResult of Operation:: %d\n", res);
    curl_easy_cleanup(curl);
    return 0;
}

int
nfv_node_db_resync()
{
    CURL *curl;
    CURLcode res;
	char* url = "http://localhost:8181/1.0/nfvtopology/sync";

    curl = rest_get(curl, url);
    res = curl_easy_perform(curl);
    printf("\nResult of Operation:: %d\n", res);
    curl_easy_cleanup(curl);
    return 0;
}

int
service_db_resync()
{
    CURL *curl;
    CURLcode res;
	char* url = "http://localhost:8181/1.0/service/sync";

    curl = rest_get(curl, url);
    res = curl_easy_perform(curl);
    printf("\nResult of Operation:: %d\n", res);
    curl_easy_cleanup(curl);
    return 0;
}

int
service_chain_default_db_resync()
{
    CURL *curl;
    CURLcode res;
	char* url = "http://localhost:8181/1.0/servicechdefault/sync";

    curl = rest_get(curl, url);
    res = curl_easy_perform(curl);
    printf("\nResult of Operation:: %d\n", res);
    curl_easy_cleanup(curl);
    return 0;
}

int
nfv_group_db_resync()
{
    CURL *curl;
    CURLcode res;
	char* url = "http://localhost:8181/1.0/nfvgroup/sync";

    curl = rest_get(curl, url);
    res = curl_easy_perform(curl);
    printf("\nResult of Operation:: %d\n", res);
    curl_easy_cleanup(curl);
    return 0;
}


int
register_serv_flow(uint64_t dpid, uint32_t nw_src, uint16_t vlan)
{
    CURL *curl;
    char *url="http://localhost:8181/1.0/servicech/log";
    CURLcode res;
    curl = curl_easy_init();
    int len = 0;
    char* jsonObj = calloc(1, 1024); 
    struct curl_slist *headers = NULL;
    struct in_addr ip_addr = { .s_addr = 0 };
    uint32_t nw_src_mask;
    
    /* First set the URL that is about to receive our POST. This URL can
    just as well be a https:// URL if that is what should receive the
    data. */
    nw_src_mask = make_inet_mask(32);
    ip_addr.s_addr = htonl(nw_src) & htonl(nw_src_mask);
    
    len = sprintf(jsonObj, "{ \"dpid\":\"0x00%llx\", \"port\":%d, \"ip\":\"%s\"}",
                    dpid, vlan, inet_ntoa(ip_addr));
    c_log_err("%s", jsonObj);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "charsets: utf-8");
    curl_easy_setopt(curl, CURLOPT_URL, url);

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonObj);

    res = curl_easy_perform(curl);
    printf("\nResult of Operation:: %d\n", res);
    curl_easy_cleanup(curl);
    free(jsonObj);
    return 0;
}

int
unregister_serv_flow(uint64_t dpid, uint32_t nw_src, uint16_t vlan)
{
    // FIXME : Please fill up 
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    int len = 0;
    char* url = calloc(1, 1024); 
    struct curl_slist *headers = NULL;
    struct in_addr ip_addr = { .s_addr = 0 };
    uint32_t nw_src_mask;
    
    nw_src_mask = make_inet_mask(32);
    ip_addr.s_addr = htonl(nw_src) & htonl(nw_src_mask);
    len = sprintf(url, "http://localhost:8181/1.0/servicech/log/0x00%llx/%d/%s",
                    dpid, vlan, inet_ntoa(ip_addr));
    
    c_log_err("%s", url);
    /* First set the URL that is about to receive our POST. This URL can
    just as well be a https:// URL if that is what should receive the
    data. */
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "charsets: utf-8");
    curl_easy_setopt(curl, CURLOPT_URL, url);

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
    //curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonObj);

    res = curl_easy_perform(curl);
    printf("\nResult of Operation:: %d\n", res);
    curl_easy_cleanup(curl);
    free(url);
    

    return res;
}
