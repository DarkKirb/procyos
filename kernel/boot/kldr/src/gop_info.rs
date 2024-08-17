use log::info;
use startup_info::Framebuffer;
use uefi::{
    prelude::BootServices,
    proto::console::gop::{GraphicsOutput, PixelFormat},
    Status,
};

/// This function retrieves the information about the Graphics Output Protocol (GOP) and selects the
/// mode with the highest resolution and either RGB or BGR pixel format.
/// # Errors
/// This function returns an error if the GOP protocol is not available or if it cannot be opened.
pub fn gather_gop_info(bs: &BootServices) -> uefi::Result<Framebuffer> {
    let gop_handle = bs.get_handle_for_protocol::<GraphicsOutput>()?;
    let mut gop = bs.open_protocol_exclusive::<GraphicsOutput>(gop_handle)?;

    let mut max_mp = 0;
    let mut max_mode = None;

    for (i, mode) in gop.modes(bs).enumerate() {
        let mode_info = mode.info();
        info!(
            "Mode: {}, Resolution: {}x{}, Pixel Format: {:?}",
            i,
            mode_info.resolution().0,
            mode_info.resolution().1,
            mode_info.pixel_format(),
        );
        if mode_info.pixel_format() != PixelFormat::Rgb
            && mode_info.pixel_format() != PixelFormat::Bgr
        {
            continue;
        }
        if max_mp < mode_info.resolution().0 * mode_info.resolution().1 {
            max_mp = mode_info.resolution().0 * mode_info.resolution().1;
            max_mode = Some(mode);
        }
    }

    if let Some(mode) = max_mode {
        gop.set_mode(&mode)?;

        let fb_ptr = gop.frame_buffer().as_mut_ptr() as usize;

        let fb = Framebuffer::new(
            mode.info()
                .resolution()
                .0
                .try_into()
                .map_err(|_| Status::INVALID_PARAMETER)?,
            mode.info()
                .resolution()
                .1
                .try_into()
                .map_err(|_| Status::INVALID_PARAMETER)?,
            match mode.info().pixel_format() {
                PixelFormat::Rgb => startup_info::PixelFormat::Rgb,
                PixelFormat::Bgr => startup_info::PixelFormat::Bgr,
                _ => unreachable!(),
            },
            fb_ptr,
            mode.info().stride(),
        );
        return Ok(fb);
    }

    Err(uefi::Status::NOT_FOUND.into())
}
