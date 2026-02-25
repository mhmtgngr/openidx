import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  AlertDialog,
  AlertDialogTrigger,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogFooter,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogAction,
  AlertDialogCancel,
} from './alert-dialog'

describe('AlertDialog', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
  })

  it('renders trigger button', () => {
    render(
      <AlertDialog>
        <AlertDialogTrigger asChild>
          <button type="button">Trigger</button>
        </AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Test</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )

    expect(screen.getByRole('button', { name: 'Trigger' })).toBeInTheDocument()
  })

  it('renders with title and description defined', () => {
    render(
      <AlertDialog>
        <AlertDialogTrigger asChild>
          <button type="button">Open Dialog</button>
        </AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Confirm Action</AlertDialogTitle>
            <AlertDialogDescription>This is a description</AlertDialogDescription>
          </AlertDialogHeader>
        </AlertDialogContent>
      </AlertDialog>
    )

    expect(screen.getByRole('button', { name: 'Open Dialog' })).toBeInTheDocument()
  })

  it('renders with action button', () => {
    render(
      <AlertDialog>
        <AlertDialogTrigger asChild>
          <button type="button">Trigger</button>
        </AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Title</AlertDialogTitle>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogAction>Confirm</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    )

    expect(screen.getByRole('button', { name: 'Trigger' })).toBeInTheDocument()
  })

  it('renders with cancel button', () => {
    render(
      <AlertDialog>
        <AlertDialogTrigger asChild>
          <button type="button">Trigger</button>
        </AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Title</AlertDialogTitle>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    )

    expect(screen.getByRole('button', { name: 'Trigger' })).toBeInTheDocument()
  })

  it('renders with custom className on content', () => {
    render(
      <AlertDialog>
        <AlertDialogTrigger asChild>
          <button type="button">Trigger</button>
        </AlertDialogTrigger>
        <AlertDialogContent className="custom-content">
          <AlertDialogHeader>
            <AlertDialogTitle>Title</AlertDialogTitle>
          </AlertDialogHeader>
        </AlertDialogContent>
      </AlertDialog>
    )

    expect(screen.getByRole('button', { name: 'Trigger' })).toBeInTheDocument()
  })

  it('renders with custom className on title', () => {
    render(
      <AlertDialog>
        <AlertDialogTrigger asChild>
          <button type="button">Trigger</button>
        </AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="custom-title">Title</AlertDialogTitle>
          </AlertDialogHeader>
        </AlertDialogContent>
      </AlertDialog>
    )

    expect(screen.getByRole('button', { name: 'Trigger' })).toBeInTheDocument()
  })

  it('renders with custom className on action', () => {
    render(
      <AlertDialog>
        <AlertDialogTrigger asChild>
          <button type="button">Trigger</button>
        </AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Title</AlertDialogTitle>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogAction className="custom-action">Confirm</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    )

    expect(screen.getByRole('button', { name: 'Trigger' })).toBeInTheDocument()
  })

  it('renders with multiple actions', () => {
    render(
      <AlertDialog>
        <AlertDialogTrigger asChild>
          <button type="button">Trigger</button>
        </AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Confirm Delete</AlertDialogTitle>
            <AlertDialogDescription>Are you sure?</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    )

    expect(screen.getByRole('button', { name: 'Trigger' })).toBeInTheDocument()
  })
})
