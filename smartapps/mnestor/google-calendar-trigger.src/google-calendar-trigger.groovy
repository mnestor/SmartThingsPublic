/**
 *   Google Calendar Service Manager
 *
 *   Author: started with ecobee plugin by scott and converted by qedi
 *   modified by mnestor
 *   Date: 2016-01-29
 *
 */


definition(
    name: "Google Calendar Trigger",
    namespace: "mnestor",
    author: "Mike Nestor",
    description: "Integrates SmartThings with Google Calendar to trigger events based on calendar items.",
    category: "Mode Magic",
    iconUrl: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience.png",
    iconX2Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png",
    iconX3Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png",
) {
   appSetting "clientId"
   appSetting "clientSecret"
}

preferences {
	page(name: "authentication", title: "Google Calendar", content: "authPage", nextPage: "calendarList", install: false)
    page(name: "calendarList", title: "Google Calendar", content:"calendarList", install:true)
}

mappings {
	path("/oauth/initialize") {action: [GET: "oauthInitUrl"]}
	path("/oauth/callback") {action: [GET: "callback"]}
    path("/calendarList") {action: [GET: "calendarList"]}
}

def authPage()
{
   log.debug "authPage()"

   if(!state.accessToken)
   {
      log.debug "about to create access token"
      createAccessToken()
   }

   def redirectUrl = "https://graph.api.smartthings.com/oauth/initialize?appId=${app.id}&access_token=${state.accessToken}&apiServerUrl=${getApiServerUrl()}"
   log.debug "RedirectUrl = ${redirectUrl}"

   if (!state.authToken) {
      log.debug "no oauthTokenProvided"

      return dynamicPage(name: "authentication", title: "Login", uninstall: false) {
         section("Google Authentication"){
            paragraph "Tap below to log in to Google and authorize SmartThings access. Copy and paste the access token into the field below."
            href url:redirectUrl, style:"embedded", required:true, title:"", description:"Click to enter credentials"
         }
      }
   } else {
      log.debug "already logged in"

      return dynamicPage(name: "authentication", title: "Log In", nextPage:"calendarList", uninstall: false) {
         section("Already Configured"){
            paragraph "Tap Next to continue to set up your calendar"
            href(
               name: "toCalendarList", 
               page: "calendarList", 
               style:"embedded", 
               state:"complete", 
               title:"google calendar", 
               description:"You are connected"
            )
         }
      }

   }

}

def calendarList()
{
   log.debug "calendarList()"
  
   def stats = getCalendarList()

   log.debug "device list: $stats"

   def p = dynamicPage(name: "calendarList", title: "Select Your Calendar", uninstall: true) {
      section(){
         paragraph "Tap below to see the list of calendars in your Google account and select the one you want to connect to SmartThings."
         input(name: "watchCalendars", title:"", type: "enum", required:true, multiple:true, description: "Tap to choose", metadata:[values:stats])
      }
   }
   log.debug "list p: $p"
   return p
}

def getCalendarList()
{
   log.debug "getting calendar list"
   def path = "/calendar/v3/users/me/calendarList"
   def calendarListParams = [
      uri: "https://www.googleapis.com",
      path: path,
      headers: ["Content-Type": "text/json", "Authorization": "Bearer ${state.authToken}"],
      query: [format: 'json', body: requestBody]
   ]

   log.debug "_______AUTH______ ${state.authToken}"
   log.debug "calendar list params: $calendarListParams"

   def stats = [:]
   state.action = null
   try {
      httpGet(calendarListParams) { resp ->
         resp.data.items.each { stat ->
            stats[stat.id] = stat.summary
         }
      }
   } catch (e) {
       log.debug "http error getting ${path}"
       log.debug e
       if(!state.action || state.action == "") {
          log.debug "trying again"
          state.action = "getCalendarList"
          return refreshAuthToken(this.&getCalendarList)
       } else {
          log.debug "unresolvable"
          log.error e.getResponse().getData()
       }
   }

   return stats
}

def getNextEvents(id)
{
   log.debug "getting event list"
   def pathParams = [
      maxResults: 5,
      orderBy: "startTime",
      singleEvents: "true",
      timeMin: getCurrentTime()
   ]
   
   def path = "/calendar/v3/calendars/${id}/events"
   def eventListParams = [
      uri: "https://www.googleapis.com",
      path: path,
      headers: ["Content-Type": "text/json", "Authorization": "Bearer ${state.authToken}"],
      query: pathParams
   ]

   log.debug "_______AUTH______ ${state.authToken}"
   log.debug "event list params: $eventListParams"

   def evs = []
   state.action = null
   try {
      httpGet(eventListParams) { resp ->
         evs = resp.data.items
      }
   } catch (e) {
       log.debug "http error getting ${path}"
       log.debug e
       if(!state.action || state.action == "") {
          log.debug "trying again"
          state.action = "getNextEvents"
          return refreshAuthToken(this.&getNextEvents)
       } else {
          log.debug "unresolvable"
          log.error e.getResponse().getData()
       }
   }
   return evs
}

def installed() {
   log.debug "Installed with settings: ${settings}"
   initialize()
}

def updated() {
   log.debug "Updated with settings: ${settings}"
   unsubscribe()
   initialize()
}

def initialize() {
   log.debug "initialize"
   log.debug watchCalendars

   def calendarsToDelete
   calendarsToDelete = getAllChildDevices()
   calendarsToDelete.each { deleteChildDevice(it.deviceNetworkId) }

   def d = getChildDevice(watchCalendars)
   watchCalendars.each { wc -> 
      log.debug d

      if(!d)
      {
         log.debug "creating device"
         log.debug getChildNamespace()
         log.debug getChildName()
         log.debug wc
         d = addChildDevice(getChildName(), wc)
         log.debug "created ${d.displayName} with id $wc"
      }
      else
      {
         log.debug "found ${d.displayName} with id $dni already exists"
      }

      log.debug "created calendar to watch"
   }

   runEvery30Minutes(pollHandler)
   
   pollHandler()
}

def pollHandler()
{
   log.debug "pollhandler"
   def calendarsToCheck = getAllChildDevices()
   calendarsToCheck.each { cal ->
      def ev = getNextEvents(cal.deviceNetworkId)
      log.debug "setting next event to trigger at "+ev.first().start.dateTime
      cal.setNextEvent(
      	ev.first().start.dateTime,
      	ev.first().end.dateTime,
      	ev.first().summary
      )
   }
}

def oauthInitUrl()
{
   log.debug "oauthInitUrl"
   
   state.oauthInitState = UUID.randomUUID().toString()

   def oauthParams = [
      response_type: "code",
      scope: "https://www.googleapis.com/auth/calendar.readonly",
      client_id: getAppClientId(),
      state: state.oauthInitState,
      redirect_uri: "https://graph.api.smartthings.com/oauth/callback"
      //urn:ietf:wg:oauth:2.0:oob"
   ]

   redirect(location: "https://accounts.google.com/o/oauth2/v2/auth?" + toQueryString(oauthParams))
}

def callback() {
	log.debug "state.oauthInitState ${state.oauthInitState}"
    log.debug "params.state ${params.state}"
    log.debug "callback()>> params: $params, params.code ${params.code}"

	log.debug "token request: $params.code"
	debugEvent ("token request")

	def postParams = [
		uri: "https://www.googleapis.com",
		path: "/oauth2/v3/token",
		requestContentType: "application/x-www-form-urlencoded; charset=utf-8",
		body: [
			code: params.code,
			client_secret: getAppClientSecret(),
			client_id: getAppClientId(),
			grant_type: "authorization_code",
			redirect_uri: "https://graph.api.smartthings.com/oauth/callback"
		]
	]

	log.debug postParams

	def jsonMap
	try {
		httpPost(postParams) { resp ->
			log.debug "resp"
			log.debug resp.data
			state.refreshToken = resp.data.refresh_token
            state.authToken = resp.data.access_token
			jsonMap = resp.data
		}
	} catch (e) {
		log.error "something went wrong: $e"
		log.error e.getResponse().getData()
		return
	}

	log.debug "refresh_token: $state.refreshToken"
	log.debug "authToken: $state.authToken"
	 
          
	if (state.authToken) {
		// call some method that will render the successfully connected message
		success()
	} else {
		// gracefully handle failures
		fail()
	}

  //  } else {
   //     log.error "callback() failed. Validation of state did not match. oauthState != state.oauthInitState"
    //}
}

// Example success method
def success() {
        def message = """
                <p>Your account is now connected to SmartThings!</p>
                <p>Click 'Done' to finish setup.</p>
        """
        displayMessageAsHtml(message)
}

// Example fail method
def fail() {
    def message = """
        <p>There was an error connecting your account with SmartThings</p>
        <p>Please try again.</p>
    """
    displayMessageAsHtml(message)
}

def displayMessageAsHtml(message) {
    def html = """
        <!DOCTYPE html>
        <html>
            <head>
            </head>
            <body>
                <div>
                    ${message}
                </div>
            </body>
        </html>
    """
    render contentType: 'text/html', data: html
}

private refreshAuthToken(Closure fn = {}) {
   log.debug "refreshing auth token"
   debugEvent("refreshing OAUTH token")

   if(!state.refreshToken) {
      log.warn "Can not refresh OAuth token since there is no refreshToken stored"
      log.debug state
   } else {
      def stcid = getAppClientId()

      def refreshParams = [
            method: 'POST',
            uri   : "https://www.googleapis.com",
            path  : "/oauth2/v3/token",
            body : [
               refresh_token: "${state.refreshToken}", 
               client_secret: getAppClientSecret(),
               grant_type: 'refresh_token', 
               client_id: getAppClientId()
            ],
      ]

      log.debug refreshParams

      //changed to httpPost
      try {
         def jsonMap
         httpPost(refreshParams) { resp ->
            log.debug "Token refreshed...calling saved RestAction now!"

            debugEvent("Token refreshed ... calling saved RestAction now!")

            log.debug resp

            jsonMap = resp.data

            if(resp.data) {

               log.debug resp.data
               debugEvent("Response = ${resp.data}")

               debugEvent("OAUTH Token = ${state.authToken}")
               state.authToken = resp?.data?.access_token

               if(state.action && state.action != "") {
                  log.debug "Executing next action: ${state.action}"

                  return fn()

                  //remove saved action
                  state.action = ""
               }
            }
            state.action = ""
         }
      }
      catch(Exception e) {
         log.debug "caught exception refreshing auth token: " + e
         log.error e.getResponse().getData()
      }
   }
}

def toQueryString(Map m)
{
   return m.collect { k, v -> "${k}=${URLEncoder.encode(v.toString())}" }.sort().join("&")
}

def getCurrentTime() {
   //RFC 3339 format
   //2015-06-20T11:39:45.0Z
   def d = new Date()
   return String.format("%04d-%02d-%02dT%02d:%02d:%02d.000Z"
      , d.year+1900
      , d.month+1
      , d.day
      , d.hours
      , d.minutes
      , d.seconds
   )

}

def getChildNamespace() { "qedi-r" }
def getChildName() { "Calendar Event Sensor" }

def getAppClientId() { appSettings.clientId }
def getAppClientSecret() { appSettings.clientSecret }
