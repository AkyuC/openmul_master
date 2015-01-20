import logging
import json
import colander

from app.lib import mul_nbapi as mul
from app.handler.base import BaseHandler

logger = logging.getLogger("MeterTableHandler");
logger.setLevel(logging.DEBUG)

class MeterTableHandler(BaseHandler):

    def get(self, dpid=None, meter_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - dpid: %s, meter_id : %s",dpid, meter_id)
        if dpid and meter_id is None:
            self.__get_switch_meter(dpid)
        if dpid and meter_id:
            self.__get_swigch_meter_with_id(dpid, meter_id)

    def options(self, dpid=None, meter_id=None):
        self.write("ok")

    def post(self, dpid=None, meter_id=None):
        logger.debug("request url - %s", self.get_request_uri())
        logger.debug("request params - dpid: %s, meter_id: %s",dpid, meter_id)
        body = None
        m_parms = None
        act_len = 0
        mdata_arr = []
        ret = {}
        try:
            version = mul.nbapi_get_switch_version_with_id(int(dpid, 16))
            if version == 0:
                raise Exception, 'no such switch'
            elif version == 1:
                raise Exception, 'Not supported switch OFP version'

            body = MeterSchema().deserialize(json.loads(self.request.body))
            logger.debug(str(body))

            m_parms = mul.prepare_add_meter(str(body["meter_id"]),
                                            str(body["type"]),
                                             str(body["burst"]),
                                            str(body["stats"]))
            if m_parms == None:
                raise Exception, 'malfomed input data'
            for meter_band in body["meter_bands"]:
                mdata = mul.nbapi_meter_band_add(int(dpid, 16),
                                                 act_len,
                                                 m_parms,
                                                 str(meter_band['band_type']),
                                                 str(meter_band['rate']),
                                                 str(meter_band['burst_size']),
                                                 str(meter_band['prec_level']))
                if mdata == None:
                    raise Exception, 'Malfomed meter band data'                    
                else:
                    mdata_arr.append(mdata)
                    act_len += 1

            check = mul.nbapi_meter_add(act_len,
                                    int(dpid, 16),
                                    m_parms)

            if check == 0:
                ret.update({ "meter_id" : body['meter_id'] })
            else:
                raise Exception, 'meter already exist'
        except Exception, e:
            ret.update({'error_message' : 'Failed to add meter', 'reason' : str(e)})
        finally:
            for mdata in mdata_arr:
                mul.nbapi_mdata_free(mdata)
            mul.nbapi_meter_free(act_len, m_parms)
            self.finish(ret)

    def put(self, dpid=None, meter_id=None):
        pass

    def delete(self, dpid=None, meter_id=None):
        check = mul.nbapi_delete_meter(int(dpid, 16), int(meter_id,16));
        if check == 0:
            self.write({ "meter_id" : meter_id })
        else:
            self.write({'error_message' : 'failed to delete meter'})

    def __get_switch_meter(self, dpid):
        ret = {}
        res = []
        try:
            version = mul.nbapi_get_switch_version_with_id(int(dpid, 16))
            if version == 0:
                raise Exception, 'no such switch'
            if version == 1:
                raise Exception, 'Not supported switch OPF version'
            try:
                meters = mul.get_meter(int(dpid, 16))
            except:
                meters = []
            for meter in meters:
                m_dict = self.__c_ofp_meter_mod_serialization(meter)
                res.append(m_dict)
            ret.update({'meters' : res})
        except Exception, e:
            ret.update({'error_message' : 'Failed to get meter', 'reason':str(e)})
        finally:
            self.finish(ret)

    def __get_switch_meter_with_id(self, dpid, meter_id):
        meters = None
        ret = {}
        try:
            if version == 0:
                raise Exception, 'no such switch'
            if version == 1:
                raise Exception, 'Not supported switch OFP version'
            meters = mul.get_meter(int(dpid, 16))
            for meter in meters:
                if meter_id == meter.meter_id:
                    ret = self.__c_ofp_meter_mod_serialization(meter)
            if ret is {}:
                raise Exception, 'No such meter_id'
        except Exception, e:
            ret = { 'error_message' : 'failed to get meter', 'reason' : str(e)}
        finally:
            self.finish(ret)

    def __c_ofp_meter_mod_serialization(self, meter):
        ret = {}
        meter_type = ""
        if meter.flags & mul.OFPMF_KBPS:
            meter_type = "kbps"
        elif meter.flags & mul.OFPMF_PKTPS:
            meter_type = "pktps"

        burst = ""
        if meter.flags & mul.OFPMF_BURST:
            burst = "yes"
        else:
            burst = "no"

        stats = ""
        if meter.flags & mul.OFPMF_STATS:
            stats = "yes"
        else:
            stats = "no"

        if meter.c_flags & mul.C_METER_GSTATS:
            ret.update({
                'flow_count':                 meter.flow_count,
                'byte_in_count':         meter.byte_count,
                'packet_in_count':         meter.packet_count,
                'duration_sec':         meter.duration_sec,
                'duration_nsec':         meter.duration_nsec
            })

        ret.update({
            'meter_id':                meter.meter_id,
            'type':                meter_type,
            'burst':                burst,
            'stats':                stats,
            'meter_bands':        self.__meter_band_serialization(meter)
        })

        return ret

    def __meter_band_serialization(self, meter):
        band_type = mul.nbapi_get_band_type(meter)
        rate = mul.nbapi_get_band_rate(meter)
        burst_size = mul.nbapi_get_band_burst_size(meter)
        prec_level = mul.nbapi_get_band_prec_level(meter)

        band_type = band_type.split()
        rate = rate.split()
        burst_size = burst_size.split()
        prec_level = prec_level.split()

        ret = []
        for i in range(len(band_type)):
            m_dict = {
                'band_type': band_type[i],
                'rate': rate[i],
                'burst_size': burst_size[i]
            }
            if str(prec_level[i]) != "-1":
                m_dict.update({'prec_level': prec_level[i]})
            ret.append(m_dict)
        
        return ret

class Band(colander.MappingSchema):
    band_type = colander.SchemaNode(colander.String(), validator=colander.OneOf(["dscp_remark","drop"]), missing=None)
    rate = colander.SchemaNode(colander.String(), missing='1')
    burst_size = colander.SchemaNode(colander.String(), missing='0')
    prec_level = colander.SchemaNode(colander.String(), missing=None)

class BandsList(colander.SequenceSchema):
    band = Band()

class MeterSchema(colander.MappingSchema):
    meter_id = colander.SchemaNode(colander.String())
    type = colander.SchemaNode(colander.String(), validator=colander.OneOf(["kbps","pktps"]))
    burst = colander.SchemaNode(colander.String(), validator=colander.OneOf(["yes","no"]))
    stats = colander.SchemaNode(colander.String(), validator=colander.OneOf(["yes","no"]))
    meter_bands = BandsList()
























