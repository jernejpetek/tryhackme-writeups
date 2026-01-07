## Capturing the Silverpeas Login Request

Start by opening **Burp Suite** and keep the default options selected.  
![BS1](images/BS1.png)  
![BS2](images/BS2.png)

While Burp Suite is loading, enable **FoxyProxy** in the AttackBox browser so traffic is routed through Burp.  
![FP](images/FP.png)

Once Burp Suite is open, go to the **Proxy** tab and make sure **Intercept** is set to **ON**.  
![BS3](images/BS3.png)

Open the Silverpeas login page and enter the following credentials:
- **Username:** SilverAdmin
- **Password:** SilverAdmin

Then click **Log In**.  
![LogInPage](images/LoginPage.png)

After clicking the login button, switch back to Burp Suite (if it doesn’t appear automatically). The intercepted request will be visible. Scroll to the bottom of the request and locate:

`Login=SilverAdmin&Password=SilverAdmin&DomainId=0`

![Message](images/Message.png)

Delete the `&Password=SilverAdmin` portion of the request so it only contains the username and domain.  
![NewMessage](images/NewMessage.png)

Click **Forward**, then turn **Intercept** off.  
If successful, you should now have access to the Silverpeas main interface.  
![MainFrame](images/MainFrame.png)
