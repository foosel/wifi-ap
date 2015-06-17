class ApError(Exception):
	pass

class ApInterfaceError(ApError):
	def __init__(self, msg, cause=None):
		ApError.__init__(self, msg)
		self.cause = cause

class ApSchemeError(ApError):
	def __init__(self, msg, cause=None):
		ApError.__init__(self, msg)
		self.cause = cause

class ApBindError(ApError):
	def __init__(self, msg, cause=None):
		ApError.__init__(self, msg)
		self.cause = cause
