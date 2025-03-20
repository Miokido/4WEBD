<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\UserType;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[Route('/api/user')]
final class UserController extends AbstractController
{
    #[Route(name: 'app_user_index', methods: ['GET'])]
    public function index(UserRepository $userRepository): Response
    {
        return new JsonResponse([
            'users' => $userRepository->findAll(),
        ]);
    }

    #[Route('/new', name: 'app_user_new', methods: ['POST'])]
    public function new(Request $request, EntityManagerInterface $entityManager, UserPasswordHasherInterface $userPasswordHasher): Response
    {
        $data = json_decode($request->getContent(), true);
        $user = new User();
        $form = $this->createForm('App\Form\UserType', $user);
        $form->submit($data);
        $user->setPassword(
            $userPasswordHasher->hashPassword(
                $user,
                $form->get('plainPassword')->getData()
            )
        );
        $entityManager->persist($user);
        $entityManager->flush();
        return new JsonResponse($user);
    }

    #[Route('/show/{id}', name: 'app_user_show', methods: ['GET'])]
    public function show(User $user): Response
    {
        return new JsonResponse(['user' => $user]);
    }

    #[Route('/{id}/edit', name: 'app_user_edit', methods: ['PUT'])]
    public function edit(Request $request, User $user, EntityManagerInterface $entityManager, UserPasswordHasherInterface $userPasswordHasher): Response
    {
        $data = json_decode($request->getContent(), true);
        $form = $this->createForm('App\Form\UserType', $user);
        $form->submit($data);
        $user->setPassword(
            $userPasswordHasher->hashPassword(
                $user,
                $form->get('plainPassword')->getData()
            )
        );
        $entityManager->persist($user);
        $entityManager->flush();
        return new JsonResponse($user);
    }

    #[Route('/{id}', name: 'app_user_delete', methods: ['DELETE'])]
    public function delete(Request $request, User $user, EntityManagerInterface $entityManager): Response
    {
        if ($this->isCsrfTokenValid('delete'.$user->getId(), $request->getPayload()->getString('_token'))) {
            $entityManager->remove($user);
            $entityManager->flush();
        }

        return new JsonResponse('OK');
    }

    #[Route('/validate/', name: 'validate_token', methods: ['GET'])]
    public function validateToken(Request $request, EntityManagerInterface $entityManager, JWTEncoderInterface $jwtEncoder, TokenStorageInterface $tokenStorage): JsonResponse
    {
        $token = str_replace('Bearer ', '', $request->headers->get('Authorization'));

        try {
            $decodedToken = $jwtEncoder->decode($token);
            $user = $tokenStorage->getToken()?->getUser();

            if (!$user || !is_object($user)) {
                return $this->json(['error' => 'Invalid token or user not found'], 401);
            }

            return $this->json(['status' => 'valid', 'user' => $user->getUserIdentifier()], 200);
        } catch (\Exception $e) {
            return $this->json(['error' => 'Invalid token'], 401);
        }
    }
}
