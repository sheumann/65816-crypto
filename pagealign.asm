* Dummy segment to be linked first to set 256-byte (page) alignment.
* This needs to be linked before the root file generated by ORCA/C.
	align 256
dummy	private
	end
