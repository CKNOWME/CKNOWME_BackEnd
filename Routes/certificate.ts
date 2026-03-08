import express, { Request, Response } from "express";
import { Cert } from "../DB/cert.ts";
import { User } from "../DB/user.ts";
import { getuserJWT } from "../auth.ts";

const router = express.Router();

router.post("/add", async (req: Request, res: Response) => {
    try {
        if(req.body.title ==null || req.body.issuer==null || req.body.date==null){
            return res.status(400).json({ error: "Missing Params" });
        }
        const cert_id = crypto.randomUUID();
        const cert = new Cert({
            id: cert_id,
            title: req.body.title,
            issuer: req.body.issuer,
            description: req.body.description || "null",
            date: req.body.date,
            pdfUrl: req.body.pdfUrl || "null",
            verifyUrl: req.body.verifyUrl || "null",
            category: req.body.category || "General",
        });
        await cert.save();
        const jwt = req.cookies.bearer;
        if(jwt){
            const getUsername = await getuserJWT(jwt);
            if(getUsername != "error"){
                const user = await User.findOne({username:getUsername});
                if(user){
                    user.certs.push(cert_id);
                    await user.save();
                    return res.status(200).json({ success: "OK", username: getUsername, certId: cert.id });
                }
            }
        }
        return res.status(404).json({ error: "Please login again" });
    } catch (err: Error | any) {
        return res.status(500).json({ error: "Internal Server Error"+err });
    }
});

router.put("id/:id", async (req: Request, res: Response) => {
    try {
        const checkAuth = await getuserJWT(req.cookies.bearer);
        if(checkAuth == "error"){
            return res.status(404).json({ error: "Please login again" });
        }
        const user = await User.findOne({username:checkAuth});
        if(!user){
            return res.status(404).json({ error: "Please login again" });
        }
        if(!user.certs.includes(req.params.id)){
            return res.status(403).json({ error: "Forbidden - Not your certificate" });
        }
        const cert = await Cert.findOne({id:req.params.id});
        if(!cert){
            return res.status(404).json({ error: "Not found" });
        }
        cert.title = req.body.title || cert.title;
        cert.issuer = req.body.issuer || cert.issuer;
        cert.description = req.body.description || cert.description;
        cert.date = req.body.date || cert.date;
        cert.pdfUrl = req.body.pdfUrl || cert.pdfUrl;
        cert.verifyUrl = req.body.verifyUrl || cert.verifyUrl;
        cert.category = req.body.category || cert.category;
        await cert.save();
        res.status(200).json({ success: "OK", certId: cert.id });
    } catch (_err: Error | any) {
        res.status(500).json({ error: "Internal Server Error" });
    }
});

router.get("id/:id", async (req: Request, res: Response) => {
    try {
        const cert = await Cert.findOne({id:req.params.id}).select("-__v -_id");
        if(!cert){
            return res.status(404).json({ error: "Not found" });
        }
        res.status(200).json({ success: "OK", cert });
    } catch (_err: Error | any) {
        res.status(500).json({ error: "Internal Server Error" });
    }
});

router.delete("id/:id", async (req: Request, res: Response) => {
    try {
        const checkAuth = await getuserJWT(req.cookies.bearer);
        if(checkAuth == "error"){
            return res.status(404).json({ error: "Please login again" });
        }
        const user = await User.findOne({username:checkAuth});
        if(!user){
            return res.status(404).json({ error: "Please login again" });
        }
        if(!user.certs.includes(req.params.id)){
            return res.status(403).json({ error: "Forbidden - Not your certificate" });
        }
        const cert = await Cert.findOneAndDelete({id:req.params.id});
        if(!cert){
            return res.status(404).json({ error: "Not found" });
        }
        await User.updateMany(
            { certs: cert.id },
            { $pull: { certs: cert.id } }
        );
        res.status(200).json({ success: "OK", certId: cert.id });
    } catch (_err: Error | any) {
        res.status(500).json({ error: "Internal Server Error" });
    }
});

router.get("/all", async (_req: Request, res: Response) => {
    try {
        const checkAuth = await getuserJWT(_req.cookies.bearer);
        if(checkAuth == "error"){
            return res.status(404).json({ error: "Please login again" });
        }
        const user = await User.findOne({username:checkAuth});
        if(!user){
            return res.status(404).json({ error: "Please login again" });
        }
        const userCerts = user.certs;
        const certs = await Cert.find({id: {$in: userCerts}}).select("-__v -_id");
        res.status(200).json({ success: "OK", certs });
    } catch (_err: Error | any) {
        res.status(500).json({ error: "Internal Server Error" });
    }
});

export default router;