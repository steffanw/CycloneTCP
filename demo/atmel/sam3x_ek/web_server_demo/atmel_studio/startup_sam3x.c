//Dependencies
#include "sam3x.h"

//Linker file constants
extern uint32_t _sfixed;
extern uint32_t _efixed;
extern uint32_t _etext;
extern uint32_t _srelocate;
extern uint32_t _erelocate;
extern uint32_t _szero;
extern uint32_t _ezero;
extern uint32_t _sstack;
extern uint32_t _estack;

//Function declaration
void SystemInit(void);
void __libc_init_array(void);
int main(void);

//Default empty handler
void Default_Handler(void);

//Cortex-M3 core handlers
void Reset_Handler      (void);
void NMI_Handler        (void) __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler  (void) __attribute__((weak, alias("Default_Handler")));
void MemManage_Handler  (void) __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler   (void) __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler (void) __attribute__((weak, alias("Default_Handler")));
void SVC_Handler        (void) __attribute__((weak, alias("Default_Handler")));
void DebugMon_Handler   (void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler     (void) __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler    (void) __attribute__((weak, alias("Default_Handler")));

//Peripheral handlers
void SUPC_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void RSTC_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void RTC_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void RTT_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void WDT_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void PMC_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void EFC0_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void EFC1_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void UART_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void SMC_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void SDRAMC_IRQHandler  (void) __attribute__((weak, alias("Default_Handler")));
void PIOA_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void PIOB_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void PIOC_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void PIOD_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void PIOE_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void PIOF_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void USART0_IRQHandler  (void) __attribute__((weak, alias("Default_Handler")));
void USART1_IRQHandler  (void) __attribute__((weak, alias("Default_Handler")));
void USART2_IRQHandler  (void) __attribute__((weak, alias("Default_Handler")));
void USART3_IRQHandler  (void) __attribute__((weak, alias("Default_Handler")));
void HSMCI_IRQHandler   (void) __attribute__((weak, alias("Default_Handler")));
void TWI0_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void TWI1_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void SPI0_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void SPI1_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void SSC_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void TC0_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void TC1_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void TC2_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void TC3_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void TC4_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void TC5_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void TC6_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void TC7_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void TC8_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void PWM_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void ADC_IRQHandler     (void) __attribute__((weak, alias("Default_Handler")));
void DACC_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void DMAC_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void UOTGHS_IRQHandler  (void) __attribute__((weak, alias("Default_Handler")));
void TRNG_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void EMAC_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void CAN0_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));
void CAN1_IRQHandler    (void) __attribute__((weak, alias("Default_Handler")));

//Vector table
__attribute__((section(".vectors")))
const uint32_t vectorTable[61] =
{
	//Initial stack pointer
   (uint32_t) (&_estack),

   //Core handlers
   (uint32_t) Reset_Handler,
   (uint32_t) NMI_Handler,
   (uint32_t) HardFault_Handler,
   (uint32_t) MemManage_Handler,
   (uint32_t) BusFault_Handler,
   (uint32_t) UsageFault_Handler,
   (uint32_t) 0,
   (uint32_t) 0,
   (uint32_t) 0,
   (uint32_t) 0,
   (uint32_t) SVC_Handler,
   (uint32_t) DebugMon_Handler,
   (uint32_t) 0,
   (uint32_t) PendSV_Handler,
   (uint32_t) SysTick_Handler,

   //Peripheral handlers
   (uint32_t) SUPC_IRQHandler,   //Supply Controller
   (uint32_t) RSTC_IRQHandler,   //Reset Controller
   (uint32_t) RTC_IRQHandler,    //Real Time Clock
   (uint32_t) RTT_IRQHandler,    //Real Time Timer
   (uint32_t) WDT_IRQHandler,    //Watchdog Timer
   (uint32_t) PMC_IRQHandler,    //PMC
   (uint32_t) EFC0_IRQHandler,   //EFC 0
   (uint32_t) EFC1_IRQHandler,   //EFC 1
   (uint32_t) UART_IRQHandler,   //UART
   (uint32_t) SMC_IRQHandler,    //SMC
   (uint32_t) SDRAMC_IRQHandler, //SDRAMC
   (uint32_t) PIOA_IRQHandler,   //Parallel IO Controller A
   (uint32_t) PIOB_IRQHandler,   //Parallel IO Controller B
   (uint32_t) PIOC_IRQHandler,   //Parallel IO Controller C
   (uint32_t) PIOD_IRQHandler,   //Parallel IO Controller D
   (uint32_t) PIOE_IRQHandler,   //Parallel IO Controller E
   (uint32_t) PIOF_IRQHandler,   //Parallel IO Controller F
   (uint32_t) USART0_IRQHandler, //USART 0
   (uint32_t) USART1_IRQHandler, //USART 1
   (uint32_t) USART2_IRQHandler, //USART 2
   (uint32_t) USART3_IRQHandler, //USART 3
   (uint32_t) HSMCI_IRQHandler,  //MCI
   (uint32_t) TWI0_IRQHandler,   //TWI 0
   (uint32_t) TWI1_IRQHandler,   //TWI 1
   (uint32_t) SPI0_IRQHandler,   //SPI 0
   (uint32_t) SPI1_IRQHandler,   //SPI 1
   (uint32_t) SSC_IRQHandler,    //SSC
   (uint32_t) TC0_IRQHandler,    //Timer Counter 0
   (uint32_t) TC1_IRQHandler,    //Timer Counter 1
   (uint32_t) TC2_IRQHandler,    //Timer Counter 2
   (uint32_t) TC3_IRQHandler,    //Timer Counter 3
   (uint32_t) TC4_IRQHandler,    //Timer Counter 4
   (uint32_t) TC5_IRQHandler,    //Timer Counter 5
   (uint32_t) TC6_IRQHandler,    //Timer Counter 6
   (uint32_t) TC7_IRQHandler,    //Timer Counter 7
   (uint32_t) TC8_IRQHandler,    //Timer Counter 8
   (uint32_t) PWM_IRQHandler,    //PWM
   (uint32_t) ADC_IRQHandler,    //ADC controller
   (uint32_t) DACC_IRQHandler,   //DAC controller
   (uint32_t) DMAC_IRQHandler,   //DMA Controller
   (uint32_t) UOTGHS_IRQHandler, //USB OTG High Speed
   (uint32_t) TRNG_IRQHandler,   //True Random Number Generator
   (uint32_t) EMAC_IRQHandler,   //Ethernet MAC
   (uint32_t) CAN0_IRQHandler,   //CAN Controller 0
   (uint32_t) CAN1_IRQHandler    //CAN Controller 1
};


/**
 * @brief Reset handler
 **/

void Reset_Handler(void)
{
   uint32_t *src;
   uint32_t *dest;

   //System initialization
   SystemInit();

   //Initialize the relocate segment
   src = &_etext;
   dest = &_srelocate;

   if(src != dest)
   {
      while(dest < &_erelocate)
	  {
         *dest++ = *src++;
      }
   }

   //Clear the zero segment
   for(dest = &_szero; dest < &_ezero;)
   {
      *dest++ = 0;
   }

   //Set the vector table base address
   src = (uint32_t *) & _sfixed;
   SCB->VTOR = ((uint32_t) src & SCB_VTOR_TBLOFF_Msk);

   if(((uint32_t) src >= IRAM0_ADDR) && ((uint32_t) src < NFC_RAM_ADDR))
   {
      SCB->VTOR |= (1 << SCB_VTOR_TBLBASE_Pos);
   }

   //C library initialization
   __libc_init_array();

   //Branch to main function
   main();

   //Endless loop
   while(1);
}


/**
 * @brief Default interrupt handler
 **/

void Default_Handler(void)
{
   while(1)
   {
   }
}
