import { Router, Request, Response } from 'express';

const router = Router();

const ActionPath = {
    signin: 'signin',
    logout: 'logout'
};

// Test with template literal and variable
router.post(`/${ActionPath.signin}`, async (req: Request, res: Response) => {
    res.send('signin ok');
});

// Test with simple string literal
router.get('/health', (req: Request, res: Response) => {
    res.send('ok');
});

// Test with multiple middlewares
const validate = (req, res, next) => next();
router.put('/update', validate, async (req: Request, res: Response) => {
    res.send('updated');
});

export default router;
