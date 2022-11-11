/******************************************************************************
 *
 * Copyright(c) 2007 - 2012 Realtek Corporation. All rights reserved.
 *                                        
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110, USA
 *
 *
 ******************************************************************************/


use crate::prelude::*;
use crate::rtw_hal::hal_data::HAL_DATA_TYPE;
use crate::rtw_hal::hal_intf::adapter::Adapter;
use crate::rtw_hal::hal_intf::hal_data::HalData;
use crate::rtw_hal::hal_intf::hal_data::HalDataPriv;

pub fn sreset_init_value(padapter: &Adapter) {
    let pHalData = padapter.hal_data;
    let psrtpriv = &pHalData.srestpriv;

    psrtpriv.silent_reset_inprogress = false;
    psrtpriv.Wifi_Error_Status = WIFI_STATUS_SUCCESS;
    psrtpriv.last_tx_time = 0;
    psrtpriv.last_tx_complete_time = 0;
}

pub fn sreset_reset_value(padapter: &Adapter) {
    let pHalData = padapter.hal_data;
    let psrtpriv = &pHalData.srestpriv;

    psrtpriv.silent_reset_inprogress = false;
    psrtpriv.Wifi_Error_Status = WIFI_STATUS_SUCCESS;
    psrtpriv.last_tx_time = 0;
    psrtpriv.last_tx_complete_time = 0;
}


pub fn sreset_set_wifi_error_status(padapter: &Adapter, status: u8) {
    let pHalData = padapter.hal_data;
    let psrtpriv = &pHalData.srestpriv;

    psrtpriv.Wifi_Error_Status = status;
}

pub fn sreset_set_wifi_error_status(padapter: &Adapter, status: u8) {
    let pHalData = padapter.hal_data;
    let psrtpriv = &pHalData.srestpriv;

    psrtpriv.Wifi_Error_Status = status;
}

pub fn sreset_set_trigger_point(padapter: &Adapter, tgp: i32) {
    let pHalData = padapter.hal_data;
    let psrtpriv = &pHalData.srestpriv;

    psrtpriv.dbg_trigger_point = tgp;
}

pub fn sreset_inprogress(padapter: &Adapter) -> bool {
    let pHalData = padapter.hal_data;
    let psrtpriv = &pHalData.srestpriv;

    psrtpriv.silent_reset_inprogress
}

pub fn sreset_restore_security_station(padapter: &Adapter) {
    let psecuritypriv = &padapter.securitypriv;
    let pmlmeinfo = &padapter.mlmeextpriv.mlmext_info;
    let mlmepriv = &padapter.mlmepriv;
    let pstapriv = &padapter.stapriv;

    let val8: u8;

    if pmlmeinfo.auth_algo == dot11AuthAlgrthm_8021X {
        val8 = 0xcc;
    } else if padapter.wapiInfo.bWapiEnable && pmlmeinfo.auth_algo == dot11AuthAlgrthm_WAPI {
        //Disable TxUseDefaultKey, RxUseDefaultKey, RxBroadcastUseDefaultKey.
        val8 = 0x4c;
    } else {
        val8 = 0xcf;
    }
    rtw_hal_set_hwreg(padapter, HW_VAR_SEC_CFG, &val8);

    if psecuritypriv.dot11PrivacyAlgrthm == _TKIP_ || psecuritypriv.dot11PrivacyAlgrthm == _AES_ {
        let psta = rtw_get_stainfo(pstapriv, get_bssid(mlmepriv));
        if psta == null {
            //DEBUG_ERR( ("Set wpa_set_encryption: Obtain Sta_info fail \n"));
        } else {
            //pairwise key
            rtw_setstakey_cmd(padapter, psta, true);
            //group key
            rtw_set_key(padapter, psecuritypriv, psecuritypriv.dot118021XGrpKeyid, 0);
        }
    }
}

pub fn sreset_restore_network_station(padapter: &Adapter) {
    let mlmepriv = &padapter.mlmepriv;
    let pmlmeext = &padapter.mlmeextpriv;
    let pmlmeinfo = &pmlmeext.mlmext_info;

    rtw_setopmode_cmd(padapter, Ndis802_11Infrastructure);

    {
        let threshold: u8;
        // TH=1 => means that invalidate usb rx aggregation
        // TH=0 => means that validate usb rx aggregation, use init value.
        if mlmepriv.htpriv.ht_option {
            if padapter.registrypriv.wifi_spec == 1 {
                threshold = 1;
            } else {
                threshold = 0;
            }
            rtw_hal_set_hwreg(padapter, HW_VAR_RXDMA_AGG_PG_TH, &threshold);
        } else {
            threshold = 1;
            rtw_hal_set_hwreg(padapter, HW_VAR_RXDMA_AGG_PG_TH, &threshold);
        }
    }

    set_channel_bwmode(padapter, pmlmeext.cur_channel, pmlmeext.cur_ch_offset, pmlmeext.cur_bwmode);

    //disable dynamic functions, such as high power, DIG
    //Switch_DM_Func(padapter, DYNAMIC_FUNC_DISABLE, _FALSE);

    rtw_hal_set_hwreg(padapter, HW_VAR_BSSID, pmlmeinfo.network.MacAddress);

    {
        let join_type = 0;
        rtw_hal_set_hwreg(padapter, HW_VAR_MLME_JOIN, &join_type);
    }

    Set_MSR(padapter, pmlmeinfo.state & 0x3);

    mlmeext_joinbss_event_callback(padapter, 1);
    //restore Sequence No.
    rtw_write8(padapter, 0x4dc, padapter.xmitpriv.nqos_ssn);

    sreset_restore_security_station(padapter);
}


pub fn sreset_restore_network_status(padapter: &mut Adapter) {
    let mlmepriv = &padapter.mlmepriv;
    let pmlmeext = &padapter.mlmeextpriv;
    let pmlmeinfo = &pmlmeext.mlmext_info;

    if check_fwstate(mlmepriv, WIFI_STATION_STATE) {
        DBG_871X!(FUNC_ADPT_FMT" fwstate:0x%08x - WIFI_STATION_STATE\n", FUNC_ADPT_ARG!(padapter), get_fwstate(mlmepriv));
        sreset_restore_network_station(padapter);
    } else if check_fwstate(mlmepriv, WIFI_AP_STATE) {
        DBG_871X!(FUNC_ADPT_FMT" fwstate:0x%08x - WIFI_AP_STATE\n", FUNC_ADPT_ARG!(padapter), get_fwstate(mlmepriv));
        rtw_ap_restore_network(padapter);
    } else if check_fwstate(mlmepriv, WIFI_ADHOC_STATE) {
        DBG_871X!(FUNC_ADPT_FMT" fwstate:0x%08x - WIFI_ADHOC_STATE\n", FUNC_ADPT_ARG!(padapter), get_fwstate(mlmepriv));
    } else {
        DBG_871X!(FUNC_ADPT_FMT" fwstate:0x%08x - ???\n", FUNC_ADPT_ARG!(padapter), get_fwstate(mlmepriv));
    }
}

pub fn sreset_stop_adapter(padapter: &mut Adapter) {
    let pmlmepriv = &padapter.mlmepriv;
    let pxmitpriv = &padapter.xmitpriv;

    if padapter == null {
        return;
    }

    DBG_871X!(FUNC_ADPT_FMT"\n", FUNC_ADPT_ARG!(padapter));

    if !rtw_netif_queue_stopped(padapter.pnetdev) {
        rtw_netif_stop_queue(padapter.pnetdev);
    }

    rtw_cancel_all_timer(padapter);

    if check_fwstate(pmlmepriv, _FW_UNDER_SURVEY) {
        rtw_scan_abort(padapter);
    }
    if check_fwstate(pmlmepriv, _FW_UNDER_LINKING) {
        _rtw_join_timeout_handler(padapter);
    }
}

pub fn sreset_start_adapter(padapter: &mut Adapter) {
    let pmlmepriv = &padapter.mlmepriv;
    let pxmitpriv = &padapter.xmitpriv;

    if padapter == null {
        return;
    }

    DBG_871X!(FUNC_ADPT_FMT"\n", FUNC_ADPT_ARG!(padapter));

    if check_fwstate(pmlmepriv, _FW_LINKED) {
        sreset_restore_network_status(padapter);
    }

    _set_timer(&padapter.mlmepriv.dynamic_chk_timer, 2000);

    if rtw_netif_queue_stopped(padapter.pnetdev) {
        rtw_netif_wake_queue(padapter.pnetdev);
    }
}

pub fn sreset_reset(padapter: &mut Adapter) {
    let pHalData = GET_HAL_DATA!(padapter);
    let psrtpriv = &pHalData.srestpriv;
    let pwrpriv = &padapter.pwrctrlpriv;
    let pmlmepriv = &padapter.mlmepriv;
    let pxmitpriv = &padapter.xmitpriv;
    let start = rtw_get_current_time();

    DBG_871X!(FUNC_ADPT_FMT"\n", FUNC_ADPT_ARG!(padapter));

    psrtpriv.Wifi_Error_Status = WIFI_STATUS_SUCCESS;

    psrtpriv.silent_reset_inprogress = true;
    pwrpriv.change_rfpwrstate = rf_off;

    sreset_stop_adapter(padapter);
    if concurrent_mode {
        sreset_stop_adapter(padapter.pbuddy_adapter);
    }
    if ips_mode {
        ips_enter(padapter);
        ips_leave(padapter);
    }
    sreset_start_adapter(padapter);
    if concurrent_mode {
        sreset_start_adapter(padapter.pbuddy_adapter);
    }

    psrtpriv.silent_reset_inprogress = false;
    _exit_critical_mutex(&psrtpriv.silentreset_mutex, &irqL);

    DBG_871X!(FUNC_ADPT_FMT" done in %d ms\n", FUNC_ADPT_ARG!(padapter), rtw_get_passing_time_ms(start));
}

