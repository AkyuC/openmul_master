import logging
import json
import colander

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

logger = logging.getLogger("GroupHandler")
logger.setLevel(logging.DEBUG)

class GroupTableHandler(BaseHandler):

    def get(self, dpid=None, group_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - dpid: %s, group_id: %s", dpid, group_id)
        if dpid and group_id is None:
            self.__get_switch_group(dpid)
        elif dpid and group_id:
            self.write("get specific group")

    def options(self, dpid=None, group_id=None):
        self.write("ok")

    def post(self, dpid=None, group_id=None):
        logger.debug("requst url - %s", self.get_request_uri())
        logger.debug("requst params - dpid : %s, group_id: %s", dpid, group_id)
        ret = {}
        body = None
        group = None
        mdata_list = []
        act_len = 0
        try:
            version = mul.nbapi_get_switch_version_with_id(int(dpid, 16))
            if version == 0:
                raise Exception, 'no such switch'
            elif version == 1:
                raise Exception, 'Not supported switch OFP version'
            body = GroupSchema().deserialize(json.loads(self.request.body))
            group = mul.prepare_add_group(str(body['group_id']), str(body['type']))
            for action_bucket in body['action_buckets']:
                mdata = mul.nbapi_group_mdata_alloc(int(dpid, 16))
                if mdata is None:
                    raise Exception, 'failed to set mdata'
                mdata_list.append(mdata)
                for action in action_bucket['actions']:
                    check = mul.nbapi_action_to_mdata(mdata, str(action['action']), str(action['value']))
                    if check is not 0:
                        raise Exception, 'Malformed action data '+str(action['action'])+" : "+str(action['value'])
                mul.nbapi_group_action_add(act_len, group, mdata, str(action_bucket['weight']), str(action_bucket['ff_port']), str(action_bucket['ff_group']))
                act_len +=1
            check = mul.nbapi_group_add(act_len, int(dpid, 16), group)
            if check == 0:
                ret.update({"group_id" : str(body['group_id'])})
            else:
                raise Exception, 'failed to add group'
        except Exception, e:
            ret.update({"error_message" : "failed to add group", "reason" : str(e)})
        finally:
            for mdata in mdata_list:
                mul.nbapi_mdata_free(mdata)
            if group:
                mul.nbapi_group_free(act_len, group)
            self.finish(ret)

    def put(self, dpid=None, group_id=None):
        pass

    def delete(self, dpid=None, group_id=None):
        check = mul.nbapi_group_del(int(dpid, 16), int(group_id, 16))
        if check == 0:
            self.write({"group_id":group_id})
        else:
            self.write({'error_message' : 'Failed to delete group', 'reason' : 'no such group'})

    def __get_switch_group(self, dpid):
        ret = {}
        try :
            version = mul.nbapi_get_switch_version_with_id(int(dpid,16))
            if version == 1:
                raise Exception, 'Not supported switch OFP version'
            elif version == 0:
                raise Exception, 'no such switch'
            ret = {}
            try:
                groups = mul.get_group(int(dpid, 16))
            except:
                groups = []
            g_list = []
            for group in groups:
                g_dict = self.__c_ofp_group_mod_serialization(group)
                g_list.append(g_dict)
            ret = {"groups" : g_list }
        except Exception, e:
            ret = {'error_message' : 'Failed to get group', 'reason' : str(e)}
        finally:
            self.finish(ret)

    def __c_ofp_group_mod_serialization(self, group):
        group_type = ""
        if group.type & mul.OFPGT_FF:
            group_type = "Unknown"
        if group.type is 0:
            group_type = "all"
        if group.type is 1:
            group_type = "select"
        if group.type is 2:
            group_type = "indirect"
        if group.type is 3:
            group_type = "ff"
        if group.flags & mul.C_GRP_RESIDUAL:
            group_type = "init-unknown"

        group_flags = ""
        if group.flags & mul.C_GRP_EXPIRED:
            group_flags = "Expired"
        if group.flags & mul.C_GRP_NOT_INSTALLED:
            group_flags = "Not-verified"
        
        return {
            'group_id':         group.group_id,
            'type':                group_type,
            'flags' :                 group_flags,
            'byte_count':        group.byte_count,
            'packet_count':        group.packet_count,
            'duration_sec':        group.duration_sec,
            'duration_nsec':        group.duration_nsec,
            'action_buckets':   self.__c_ofp_bkt_serialization(group)
        }

    def __c_ofp_bkt_serialization(self, group):
        str_actions = mul.nbapi_dump_single_group_bkt(group)
        if str_actions:
            return eval(str(str_actions))
        else:
            return ""

class Action(colander.MappingSchema):
    action_type =[
        'OUTPUT',
        'SET_VLAN_VID',
        'SET_VLAN_PCP',
        'STRIP_VLAN',
        'SET_DL_SRC',
        'SET_DL_DST',
        'SET_NW_SRC',
        'SET_NW_DST',
        'SET_NW_TOS',
        'SET_TP_SRC',
        'SET_TP_DST',

        #OFP131_ACTION
        'CP_TTL_OUT',
        'CP_TTL_IN',
        'NOT_USED',
        'NOT_USED2',
        'SET_MPLS_TTL',
        'DEC_MPLS_TTL',
        'PUSH_VLAN',
        'POP_VLAN',
        'PUSH_MPLS',
        'POP_MPLS',
        'SET_QUEUE',
        'GROUP',
        'SET_NW_TTL',
        'DEC_NW_TTL',
        'SET_FIELD',
        'PUSH_PBB',
        'POP_PBB',

        #SET_FIELD_ACTIONS
        'SET_ETH_TYPE',
        'SET_MPLS_LABEL',
        'SET_MPLS_TC',
        'SET_MPLS_BOS',
        'SET_UDP_SPORT',
        'SET_UDP_DPORT',
        'SET_TCP_SPORT',
        'SET_TCP_DPORT'

    ]
    action = colander.SchemaNode(colander.String(), validator=colander.OneOf(action_type))
    value = colander.SchemaNode(colander.String(), missing=None)

class ActionList(colander.SequenceSchema):
    action = Action()

class ActionBucket(colander.MappingSchema):
    weight = colander.SchemaNode(colander.String(), missing=None)
    ff_port = colander.SchemaNode(colander.String(), missing=None)
    ff_group = colander.SchemaNode(colander.String(), missing=None)
    actions = ActionList()
    

class BucketList(colander.SequenceSchema):
    action_bucket = ActionBucket()

class GroupSchema(colander.MappingSchema):
    group_id = colander.SchemaNode(colander.String(), missing=None,
                                   validator=colander.OneOf(["%d" %i for i in range(65536)]))
    type = colander.SchemaNode(colander.String(), validator=colander.OneOf(['all','ff','indirect','select']))
    action_buckets = BucketList()
