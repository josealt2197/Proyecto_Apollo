using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Proyecto_Apollo.Models;
using System.Net.Mail;
using System.Net;
using System.Web.Security;

namespace Proyecto_Apollo.Controllers
{
    public class UserController : Controller
    {
       //Registration Action
        [HttpGet]
        public ActionResult Registration()
        {
            return View();
        }
        //Registration POST action 
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Registration([Bind(Exclude = "IsEmailVerified,ActivationCode")] User user)
        {
            bool Status = false;
            string message = "";
            //
            // Model Validation 
            if (ModelState.IsValid)
            {

                #region //Email is already Exist 
                var isExist = IsEmailExist(user.EmailID);
                if (isExist)
                {
                    ModelState.AddModelError("EmailExist", "Ya existe una cuenta con el correo electrónico ingresado");
                    return View(user);
                }
                #endregion

                #region Generate Activation Code 
                user.ActivationCode = Guid.NewGuid();
                #endregion

                #region  Password Hashing 
                user.Password = Crypto.Hash(user.Password);
                user.ConfirmPassword = Crypto.Hash(user.ConfirmPassword); //
                #endregion
                user.IsEmailVerified = false;

                #region Save to Database
                using (MyDatabaseEntities dc = new MyDatabaseEntities())
                {
                    dc.Users.Add(user);
                    dc.SaveChanges();

                    //Send Email to User
                    SendVerificationLinkEmail(user.EmailID, user.ActivationCode.ToString());
                    message = "Registro realizado correctamente. El enlace de activación de la cuenta" + 
                        "ha sido enviado a su correo electrónico: " + user.EmailID;
                    Status = true;
                }
                #endregion
            }
            else
            {
                message = "Solicitud no válida";
            }

            ViewBag.Message = message;
            ViewBag.Status = Status;
            return View(user);
        }
        //Verify Account  
        
        [HttpGet]
        public ActionResult VerifyAccount(string id)
        {
            bool Status = false;
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                dc.Configuration.ValidateOnSaveEnabled = false; // This line I have added here to avoid 
                                                                // Confirm password does not match issue on save changes
                var v = dc.Users.Where(a => a.ActivationCode == new Guid(id)).FirstOrDefault();
                if (v != null)
                {
                    v.IsEmailVerified = true;
                    dc.SaveChanges();
                    Status = true;
                }
                else
                {
                    ViewBag.Message = "Solicitud no válida.";
                }
            }
            ViewBag.Status = Status;
            return View();
        }

        //Login 
        [HttpGet]
        public ActionResult Login()
        {
            return View();
        }

        //Login POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(UserLogin login, string ReturnUrl="")
        {
            string message = "";
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var v = dc.Users.Where(a => a.EmailID == login.EmailID).FirstOrDefault();
                if (v != null)
                {
                    if (!v.IsEmailVerified)
                    {
                        ViewBag.Message = "Por favor verifique su correo electrónico antes de ingresar.";
                        return View();
                    }

                    if (string.Compare(Crypto.Hash(login.Password),v.Password) == 0)
                    {
                        int timeout = login.RememberMe ? 525600 : 20; // 525600 min = 1 year
                        var ticket = new FormsAuthenticationTicket(login.EmailID, login.RememberMe, timeout);
                        string encrypted = FormsAuthentication.Encrypt(ticket);
                        var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encrypted);
                        cookie.Expires = DateTime.Now.AddMinutes(timeout);
                        cookie.HttpOnly = true;
                        Response.Cookies.Add(cookie);


                        if (Url.IsLocalUrl(ReturnUrl))
                        {
                            return Redirect(ReturnUrl);
                        }
                        else
                        {
                            return RedirectToAction("Index", "Home");
                        }
                    }
                    else
                    {
                        message = "Alguna de sus credenciales no es correcta, intente de nuevo.";
                    }
                }
                else
                {
                    message = "Alguna de sus credenciales no es correcta, intente de nuevo.";
                }
            }
            ViewBag.Message = message;
            return View();
        }

        //Logout
        [Authorize]
        [HttpPost]
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Login", "User");
        }


        [NonAction]
        public bool IsEmailExist(string emailID)
        {
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var v = dc.Users.Where(a => a.EmailID == emailID).FirstOrDefault();
                return v != null;
            }
        }

        [NonAction]
        public void SendVerificationLinkEmail(string emailID, string activationCode, string emailFor = "VerifyAccount")
        {
            var verifyUrl = "/User/"+emailFor+"/" + activationCode;
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl);

            var fromEmail = new MailAddress("prograVcuc@gmail.com", "Apollo Transactions");
            var toEmail = new MailAddress(emailID);
            var fromEmailPassword = "cursoCUC2019"; 

            string subject = "";
            string body = "";
            if (emailFor == "VerifyAccount")
            {
                subject = "¡Su cuenta ha sido creada exitosamente!";
                body = "<br/><br/>Nos complace informarle que su cuenta de Apollo Transactions se ha" +
                    "creado correctamente. Por favor haga clic en el enlace de abajo para verificar su cuenta." +
                    " <br/><br/><a href='" + link + "'>" + link + "</a> ";

            }
            else if (emailFor == "ResetPassword")
            {
                subject = "Recuperar Contraseña";
                body = "Hi,<br/>br/>Tenemos solicitud para restablecer la contraseña de su cuenta. Haga clic en el enlace de abajo para restablecer su contraseña" +
                    "<br/><br/><a href="+link+">Reset Password link</a>";
            }


            var smtp = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromEmail.Address, fromEmailPassword)
            };

            using (var message = new MailMessage(fromEmail, toEmail)
            {
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            })
            smtp.Send(message);
        }

        //Part 3 - Forgot Password

        public ActionResult ForgotPassword()
        {
            return View();
        }

            [HttpPost]
            public ActionResult ForgotPassword(string EmailID)
            {
                //Verify Email ID
                //Generate Reset password link 
                //Send Email 
                string message = "";
                bool status = false;

                using (MyDatabaseEntities dc = new MyDatabaseEntities())
                {
                    var account = dc.Users.Where(a => a.EmailID == EmailID).FirstOrDefault();
                    if (account != null)
                    {
                        //Send email for reset password
                        string resetCode = Guid.NewGuid().ToString();
                        SendVerificationLinkEmail(account.EmailID, resetCode, "ResetPassword");
                        account.ResetPasswordCode = resetCode;
                        //This line I have added here to avoid confirm password not match issue , as we had added a confirm password property 
                        //in our model class in part 1
                        dc.Configuration.ValidateOnSaveEnabled = false;
                        dc.SaveChanges();
                        message = "El enlace para restablecer la contraseña ha sido enviado a su correo electrónico.";
                    }
                    else
                    {
                        message = "**Cuenta no encontrada**";
                    }
                }
                ViewBag.Message = message;
                return View();
            }

        public ActionResult ResetPassword(string id)
        {
            //Verify the reset password link
            //Find account associated with this link
            //redirect to reset password page
            if (string.IsNullOrWhiteSpace(id))
            {
                return HttpNotFound();
            }

            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var user = dc.Users.Where(a => a.ResetPasswordCode == id).FirstOrDefault();
                if (user != null)
                {
                    ResetPasswordModel model = new ResetPasswordModel();
                    model.ResetCode = id;
                    return View(model);
                }
                else
                {
                    return HttpNotFound();
                }
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ResetPassword(ResetPasswordModel model)
        {
            var message = "";
            if (ModelState.IsValid)
            {
                using (MyDatabaseEntities dc = new MyDatabaseEntities())
                {
                    var user = dc.Users.Where(a => a.ResetPasswordCode == model.ResetCode).FirstOrDefault();
                    if (user != null)
                    {
                        user.Password = Crypto.Hash(model.NewPassword);
                        user.ResetPasswordCode = "";
                        dc.Configuration.ValidateOnSaveEnabled = false;
                        dc.SaveChanges();
                        message = "Nueva contraseña actualizada correctamente.";
                    }
                }
            }
            else
            {
                message = "Se ha producido un error al actualizar su contraseña.";
            }
            ViewBag.Message = message;
            return View(model);
        }
    }
}