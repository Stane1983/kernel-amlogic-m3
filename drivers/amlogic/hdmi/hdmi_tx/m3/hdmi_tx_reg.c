/*
 * Amlogic M1 
 * frame buffer driver-----------HDMI_TX
 * Copyright (C) 2010 Amlogic, Inc.
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
#ifndef AVOS
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
#include <asm/uaccess.h>
#include <mach/am_regs.h>
#else
#include "ioapi.h"
#include <chipsupport/chipsupport.h>
#include <os/extend/interrupt.h>
#include <Drivers/include/peripheral_reg.h>
#include <Drivers/include/isa_reg.h>
#include <Drivers/include/mpeg_reg.h>
#include <interrupt.h>
#include "displaydev.h"
#include "policy.h"
#endif

#include "hdmi_tx_reg.h"

#ifdef AVOS
void WRITE_APB_REG(unsigned long addr, unsigned long data)
{
  *((volatile unsigned long *) (APB_BASE+addr)) = data; 
}

unsigned long READ_APB_REG(unsigned long addr)
{
    unsigned long data;
    data = *((volatile unsigned long *)(APB_BASE+addr)); 
    return data;
}        

#endif

// In order to prevent system hangup, add check_cts_hdmi_sys_clk_status() to check 
// clock gate status . If status == 0, turn on gate first and then access HDMI port.
static void cts_hdmi_sys_clk_check_status(unsigned *flag)
{
    unsigned status;
    
    status = READ_MPEG_REG(HHI_HDMI_CLK_CNTL) & (1<<8);
    if(status == 0){
        flag[0] = 1 << 8;
        // turn on clock gate
        printk("HDMI System Clock is off, now turn on \n");
        WRITE_MPEG_REG(HHI_HDMI_CLK_CNTL, READ_MPEG_REG(HHI_HDMI_CLK_CNTL)|(1<<8));
    }
    
    status = READ_MPEG_REG(HHI_GCLK_MPEG2) & (1<<4);
    if(status == 0){
        flag[1] = 1 << 4;
        // turn on clock gate
        printk("HDMI PCLK is off, now turn on \n");
        WRITE_MPEG_REG(HHI_GCLK_MPEG2, READ_MPEG_REG(HHI_GCLK_MPEG2)|(1<<4));
    }
    
    udelay(1);
}

static void cts_hdmi_sys_clk_restore_status(unsigned *flag)
{
    if(flag[0]){
        printk("HDMI System Clock is on, now turn off \n");
        WRITE_MPEG_REG(HHI_HDMI_CLK_CNTL, READ_MPEG_REG(HHI_HDMI_CLK_CNTL)&(~(1<<8)));
    }
    
    if(flag[1]){
        printk("HDMI PCLK is on, now turn off \n");
        WRITE_MPEG_REG(HHI_GCLK_MPEG2, READ_MPEG_REG(HHI_GCLK_MPEG2)&(~(1<<4)));
    }
}

unsigned long hdmi_rd_reg(unsigned long addr)
{
    unsigned long data;
    unsigned flag[2] = {0, 0};
    
    cts_hdmi_sys_clk_check_status(flag);
    WRITE_APB_REG(HDMI_ADDR_PORT, addr);
    WRITE_APB_REG(HDMI_ADDR_PORT, addr);
    
    data = READ_APB_REG(HDMI_DATA_PORT);
    //cts_hdmi_sys_clk_restore_status(flag);
    
    return (data);
}


void hdmi_wr_only_reg(unsigned long addr, unsigned long data)
{
    unsigned flag[2] = {0, 0};
    cts_hdmi_sys_clk_check_status(flag);
    WRITE_APB_REG(HDMI_ADDR_PORT, addr);
    WRITE_APB_REG(HDMI_ADDR_PORT, addr);
    
    WRITE_APB_REG(HDMI_DATA_PORT, data);
    //cts_hdmi_sys_clk_restore_status(flag);
}

void hdmi_wr_reg(unsigned long addr, unsigned long data)
{
    unsigned long rd_data;
    unsigned flag[2] = {0, 0};
    
    cts_hdmi_sys_clk_check_status(flag);
    WRITE_APB_REG(HDMI_ADDR_PORT, addr);
    WRITE_APB_REG(HDMI_ADDR_PORT, addr);
    
    WRITE_APB_REG(HDMI_DATA_PORT, data);
    rd_data = hdmi_rd_reg (addr);
    //cts_hdmi_sys_clk_restore_status(flag);
    if (rd_data != data) 
    {
        //printk("hdmi_wr_reg(%x,%x) fails to write: %x\n",addr, data, rd_data);
       //while(1){};      
    }
}


