import { Router, Request, Response, NextFunction } from 'express';

const router = Router();

// HOF Middleware
export const middlewareFactory = (config: string) => {
    return (req: Request, res: Response, next: NextFunction) => {
        console.log("Middleware config:", config);
        next();
    };
};

router.post('/hof-test', middlewareFactory('test-config'), (req: Request, res: Response) => {
    res.send('HOF test ok');
});

export default router;
