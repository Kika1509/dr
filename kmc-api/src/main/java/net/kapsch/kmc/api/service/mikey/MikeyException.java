package net.kapsch.kmc.api.service.mikey;

public class MikeyException extends Exception {

	public MikeyException() {
	}

	public MikeyException(String arg0) {
		super(arg0);
	}

	public MikeyException(Throwable e) {
		super(e.getMessage());
	}

	public MikeyException(String arg0, Throwable e) {
		super(arg0 + e.getMessage());
	}
}
