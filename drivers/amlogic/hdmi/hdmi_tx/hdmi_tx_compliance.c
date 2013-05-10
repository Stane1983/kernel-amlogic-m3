/*
 * Amlogic Meson
 * hdmitx driver-----------HDMI_TX
 * Copyright (C) 2013 Amlogic, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the named License,
 * or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/major.h>
#include <linux/platform_device.h>
#include <linux/mutex.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/delay.h>
#include <mach/am_regs.h>
#include <mach/clock.h>
#include <mach/power_gate.h>
#include <linux/clk.h>
#include <mach/clock.h>
#include <linux/vout/vinfo.h>
#include <linux/vout/enc_clk_config.h>

#include "hdmi_info_global.h"
#include "hdmi_tx_module.h"
#include "hdmi_tx_compliance.h"
#include "hdmi_tx_cec.h"
#include "hdmi_tx_hdcp.h"
#include "m3/hdmi_tx_reg.h"

// Note: 
// set P_HHI_VID_PLL_CNTL as 0x43e, get better clock performance
// while as 0x21ef, get better clock precision\
// 24 * 62 = 1488
// 24 / 8 * 495 = 1485

static void hdmitx_get_clk_better_performance(hdmitx_dev_t* hdmitx_device)
{
    if((READ_MPEG_REG(HHI_VID_PLL_CNTL) & 0x3fff ) == 0x21ef) {
        WRITE_MPEG_REG_BITS(HHI_VID_PLL_CNTL, 0x43e, 0, 15);
    }
}

void hdmitx_special_handler_audio(hdmitx_dev_t* hdmitx_device)
{

}

void hdmitx_special_handler_video(hdmitx_dev_t* hdmitx_device)
{
    if(strncmp(hdmitx_device->RXCap.ReceiverBrandName, HDMI_RX_VIEWSONIC, strlen(HDMI_RX_VIEWSONIC)) == 0) {
        if(strncmp(hdmitx_device->RXCap.ReceiverProductName, HDMI_RX_VIEWSONIC_MODEL, strlen(HDMI_RX_VIEWSONIC_MODEL)) == 0) {
            hdmitx_get_clk_better_performance(hdmitx_device);
        }
    }
}

