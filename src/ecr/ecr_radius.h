/*
 * ecr_radius.h
 *
 *  Created on: Mar 12, 2013
 *      Author: velna
 */

#ifndef ECR_RADIUS_H_
#define ECR_RADIUS_H_

#include "ecrconf.h"

#define RADIUS_CODE_ACCESS_REQUEST			1
#define RADIUS_CODE_ACCESS_ACCEPT			2
#define RADIUS_CODE_ACCESS_REJECT			3
#define RADIUS_CODE_ACCOUNTING_REQUEST		4
#define RADIUS_CODE_ACCOUNTING_RESPONSE	    5
#define RADIUS_CODE_ACCESS_CHALLENGE		11
#define RADIUS_CODE_STATUS_SERVER			12
#define RADIUS_CODE_STATUS_CLIENT			13

#define RADIUS_ATTR_USER_NAME						1
#define RADIUS_ATTR_USER_PASSWORD					2
#define RADIUS_ATTR_CHAP_PASSWORD					3
#define RADIUS_ATTR_NAS_IP_ADDRESS				    4
#define RADIUS_ATTR_NAS_PORT						5
#define RADIUS_ATTR_SERVICE_TYPE					6
#define RADIUS_ATTR_FRAMED_PROTOCOL				    7
#define RADIUS_ATTR_FRAMED_IP_ADDRESS				8
#define RADIUS_ATTR_FRAMED_IP_NETMASK				9
#define RADIUS_ATTR_FRAMED_ROUTING				    10
#define RADIUS_ATTR_FILTER_ID						11
#define RADIUS_ATTR_FRAMED_MTU					    12
#define RADIUS_ATTR_FRAMED_COMPRESSION			    13
#define RADIUS_ATTR_LOGIN_IP_HOST					14
#define RADIUS_ATTR_LOGIN_SERVICE					15
#define RADIUS_ATTR_LOGIN_TCP_PORT				    16
//(unassigned)								        17
#define RADIUS_ATTR_REPLY_MESSAGE					18
#define RADIUS_ATTR_CALLBACK_NUMBER				    19
#define RADIUS_ATTR_CALLBACK_ID					    20
//(unassigned)								        21
#define RADIUS_ATTR_FRAMED_ROUTE					22
#define RADIUS_ATTR_FRAMED_IPX_NETWORK			    23
#define RADIUS_ATTR_STATE							24
#define RADIUS_ATTR_CLASS							25
#define RADIUS_ATTR_VENDOR_SPECIFIC				    26
#define RADIUS_ATTR_SESSION_TIMEOUT				    27
#define RADIUS_ATTR_IDLE_TIMEOUT					28
#define RADIUS_ATTR_TERMINATION_ACTION			    29
#define RADIUS_ATTR_CALLED_STATION_ID				30
#define RADIUS_ATTR_CALLING_STATION_ID			    31
#define RADIUS_ATTR_NAS_IDENTIFIER				    32
#define RADIUS_ATTR_PROXY_STATE					    33
#define RADIUS_ATTR_LOGIN_LAT_SERVICE				34
#define RADIUS_ATTR_LOGIN_LAT_NODE				    35
#define RADIUS_ATTR_LOGIN_LAT_GROUP				    36
#define RADIUS_ATTR_FRAMED_APPLETALK_LINK			37
#define RADIUS_ATTR_FRAMED_APPLETALK_NETWORK		38
#define RADIUS_ATTR_FRAMED_APPLETALK_ZONE			39
#define RADIUS_ATTR_ACCT_STATUS_TYPE                40
#define RADIUS_ATTR_ACCT_DELAY_TIME                 41
#define RADIUS_ATTR_ACCT_INPUT_OCTETS               42
#define RADIUS_ATTR_ACCT_OUTPUT_OCTETS              43
#define RADIUS_ATTR_ACCT_SESSION_ID                 44
#define RADIUS_ATTR_ACCT_AUTHENTIC                  45
#define RADIUS_ATTR_ACCT_SESSION_TIME               46
#define RADIUS_ATTR_ACCT_INPUT_PACKETS              47
#define RADIUS_ATTR_ACCT_OUTPUT_PACKETS             48
#define RADIUS_ATTR_ACCT_TERMINATE_CAUSE            49
#define RADIUS_ATTR_ACCT_MULTI_SESSION_ID           50
#define RADIUS_ATTR_ACCT_LINK_COUNT                 51
#define RADIUS_ATTR_ACCT_INPUT_GIGAWORDS            52
#define RADIUS_ATTR_ACCT_OUTPUT_GIGAWORDS           53
//52-54
#define RADIUS_ATTR_EVENT_TIMESTAMP				    55
//56-59
#define RADIUS_ATTR_CHAP_CHALLENGE				    60
#define RADIUS_ATTR_NAS_PORT_TYPE					61
#define RADIUS_ATTR_PORT_LIMIT					    62
#define RADIUS_ATTR_LOGIN_LAT_PORT				    63

#define RADIUS_ATTR_NAS_PORT_ID                     87
#define RADIUS_ATTR_FRAMED_IPV6_PREFIX              97
#define RADIUS_ATTR_DELEGATED_IPV6_PREFIX           123

#define RADIUS_VID_3GPP2                            5535
#define RADIUS_VA_3GPP2_BSID                        10

#define RADIUS_VID_HUAWEI                           2011
#define RADIUS_VA_HUAWEI_NAT_PUBLIC_ADDRRESS        161
#define RADIUS_VA_HUAWEI_NAT_START_PORT             162
#define RADIUS_VA_HUAWEI_NAT_END_PORT               163

#define RADIUS_VID_CNNET                            20942
#define RADIUS_VA_CNNET_USER_ADDRESS_TYPE           120
#define RADIUS_VA_CNNET_USER_ADDRESS_LOG            121

#define RADIUS_VID_CHTEL                            10000
#define RADIUS_VA_CHTEL_OTHERAREA_ACCESS_ID         1

typedef struct ecr_radius_attr {
    u_char type;
    u_char value_len;
    u_char *value;
    struct ecr_radius_attr *vendor_attr;
    struct ecr_radius_attr *next;
} ecr_radius_attr_t;

typedef struct {
    u_char code;
    u_char id;
    u_short len;
    u_char auth[16];
    ecr_radius_attr_t *attrs;
} ecr_radius_t;

ecr_radius_t * ecr_radius_parse(u_char *p, size_t size);

void ecr_radius_destroy(ecr_radius_t *rds);

#endif /* ECR_RADIUS_H_ */
