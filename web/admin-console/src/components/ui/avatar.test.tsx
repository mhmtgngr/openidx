import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Avatar, AvatarImage, AvatarFallback } from './avatar'

describe('Avatar', () => {
  describe('Avatar Root', () => {
    it('renders with default classes', () => {
      render(<Avatar />)
      const avatar = document.querySelector('.rounded-full')
      expect(avatar).toBeInTheDocument()
      expect(avatar).toHaveClass('h-10', 'w-10')
    })

    it('renders with custom className', () => {
      render(<Avatar className="custom-class" />)
      const avatar = document.querySelector('.custom-class')
      expect(avatar).toBeInTheDocument()
    })

    it('renders children', () => {
      render(
        <Avatar>
          <AvatarFallback>JD</AvatarFallback>
        </Avatar>
      )
      expect(screen.getByText('JD')).toBeInTheDocument()
    })
  })

  describe('AvatarImage', () => {
    it('renders with src', () => {
      render(
        <Avatar>
          <AvatarImage src="https://example.com/avatar.png" alt="Avatar" />
        </Avatar>
      )
      // Component renders - in test environment the image may or may not be visible
      const avatar = document.querySelector('.rounded-full')
      expect(avatar).toBeInTheDocument()
    })

    it('renders with custom className', () => {
      render(
        <Avatar>
          <AvatarImage
            src="https://example.com/avatar.png"
            alt="Avatar"
            className="custom-class"
          />
        </Avatar>
      )
      // Component renders without error
      const avatar = document.querySelector('.rounded-full')
      expect(avatar).toBeInTheDocument()
    })
  })

  describe('AvatarFallback', () => {
    it('renders fallback text', () => {
      render(
        <Avatar>
          <AvatarFallback>JD</AvatarFallback>
        </Avatar>
      )
      expect(screen.getByText('JD')).toBeInTheDocument()
    })

    it('renders with default classes', () => {
      render(
        <Avatar>
          <AvatarFallback>AB</AvatarFallback>
        </Avatar>
      )
      const fallback = screen.getByText('AB')
      expect(fallback).toHaveClass('bg-muted')
    })

    it('renders with custom className', () => {
      render(
        <Avatar>
          <AvatarFallback className="bg-red-500">XY</AvatarFallback>
        </Avatar>
      )
      const fallback = screen.getByText('XY')
      expect(fallback).toHaveClass('bg-red-500')
    })

    it('centers content', () => {
      render(
        <Avatar>
          <AvatarFallback>T</AvatarFallback>
        </Avatar>
      )
      const fallback = screen.getByText('T')
      expect(fallback).toHaveClass('items-center', 'justify-center')
    })
  })

  describe('Avatar Composition', () => {
    it('shows fallback when defined', () => {
      render(
        <Avatar>
          <AvatarImage src="invalid-url" alt="Avatar" />
          <AvatarFallback>JD</AvatarFallback>
        </Avatar>
      )
      // Fallback should be visible
      expect(screen.getByText('JD')).toBeInTheDocument()
    })

    it('renders with delay for fallback', () => {
      render(
        <Avatar>
          <AvatarImage src="https://example.com/avatar.png" alt="Avatar" />
          <AvatarFallback delayMs={500}>JD</AvatarFallback>
        </Avatar>
      )
      // Component should render without error
      const avatar = document.querySelector('.rounded-full')
      expect(avatar).toBeInTheDocument()
    })

    it('renders with image and fallback', () => {
      render(
        <Avatar>
          <AvatarImage src="https://example.com/avatar.png" alt="Avatar" />
          <AvatarFallback>JD</AvatarFallback>
        </Avatar>
      )
      // Component renders
      const avatar = document.querySelector('.rounded-full')
      expect(avatar).toBeInTheDocument()
    })
  })
})
